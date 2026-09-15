//! Control runs, activation proofs, and what it takes to claim a clean result.
//!
//! A configured control can be bypassed, never invoked, run against the wrong
//! subject, or return a state that is not a failure and is not a pass either.
//! `docs/06-POLICY_COMPILER.md` names the consequence: promotion to an enforced
//! assurance state requires **activation evidence** -- a known violation
//! traversing the intended mediation path and producing the promised refusal,
//! with a known-good control admitted -- because unit tests prove local logic
//! and say nothing about whether the host invokes the control, preserves its
//! signal, or honours its result.
//!
//! The eight [`ControlResult`] states exist so that "nothing meaningful was
//! checked" has somewhere to go other than into a boolean's `false`, or worse
//! its `true`. `docs/02-CONSTITUTION.md` law 17 is the rule they serve: a clean
//! control result is meaningful only when evidence proves the control ran,
//! could observe its intended subject, and can fire on the real mediation path.
//!
//! WHY there is no `From<bool>`, no `Default`, and no fallible conversion into
//! `Clean`: every one of those is a place an adapter could map some other state
//! onto success, which is exactly what the state set exists to prevent.
//! [`clean_claim`] is the only route to a clean claim, and its match over the
//! eight states is exhaustive, so a state added later stops the build rather
//! than falling into whichever arm was written last.

use jiff::Timestamp;
use politeia_core::canonical::{CanonicalError, to_canonical_bytes};
use politeia_core::trust::{AdmissionKind, Admitted};
use politeia_core::{
    Delegation, DelegationId, Digest, EvidenceId, InstitutionId, InstitutionWorkspaceId,
    PolicyBundleId, PrincipalId, RuntimeGenerationId,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::authority::{AuthorityContext, AuthorityRefusal, DirectGrant};

/// Semantic action delegated to a control-run producer.
pub const RUN_POLICY_CONTROL_ACTION: &str = "run-policy-control";

/// Semantic action delegated to an activation-proof verifier.
pub const VERIFY_POLICY_CONTROL_ACTION: &str = "verify-policy-control";

/// Semantic action delegated for one inactive candidate's control exercise.
pub const QUALIFY_POLICY_CONTROL_ACTION: &str = "qualify-policy-control";

/// Exact delegation resource for one named policy control.
pub fn policy_control_resource(control: &str) -> String {
    format!("policy-control:{control}")
}

/// Derive the exact direct-grant resource for one candidate control exercise.
///
/// The readable prefix names the authority class. The suffix is a digest of
/// every semantic axis, avoiding delimiter ambiguity in caller-chosen binding
/// and control identifiers.
///
/// # Errors
///
/// Returns a canonical encoding error if the grant subject cannot be encoded.
pub fn policy_control_qualification_resource(
    generation: &RuntimeGenerationId,
    policy_digest: &Digest,
    binding: &str,
    control: &str,
    population: &Digest,
    vectors: &ControlQualificationVectorSet,
) -> Result<String, CanonicalError> {
    let bytes = to_canonical_bytes(&ControlQualificationGrantSubject {
        kind: "politeia.policy-control-qualification-grant.v1",
        generation,
        policy_digest,
        binding,
        control,
        population,
        known_good_intent: vectors.known_good_intent(),
        known_good_run: vectors.known_good_run(),
        planted_violation_intent: vectors.planted_violation_intent(),
        planted_violation_run: vectors.planted_violation_run(),
    })?;
    Ok(format!(
        "policy-control-qualification:{}",
        Digest::blake3(&bytes).as_str()
    ))
}

#[derive(Serialize)]
struct ControlQualificationGrantSubject<'a> {
    kind: &'static str,
    generation: &'a RuntimeGenerationId,
    policy_digest: &'a Digest,
    binding: &'a str,
    control: &'a str,
    population: &'a Digest,
    known_good_intent: &'a Digest,
    known_good_run: &'a EvidenceId,
    planted_violation_intent: &'a Digest,
    planted_violation_run: &'a EvidenceId,
}

/// Exact signed intents and future record identities covered by one grant.
///
/// Constructing this inert value grants no authority. Its complete canonical
/// representation must be named by the direct owner grant admitted below.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlQualificationVectorSet {
    known_good_intent: Digest,
    known_good_run: EvidenceId,
    planted_violation_intent: Digest,
    planted_violation_run: EvidenceId,
}

impl ControlQualificationVectorSet {
    /// Bind both signed intent digests to the identities reserved for their actual runs.
    pub fn new(
        known_good_intent: Digest,
        known_good_run: EvidenceId,
        planted_violation_intent: Digest,
        planted_violation_run: EvidenceId,
    ) -> Self {
        Self {
            known_good_intent,
            known_good_run,
            planted_violation_intent,
            planted_violation_run,
        }
    }

    /// Digest of the exact signed known-good operation intent.
    pub fn known_good_intent(&self) -> &Digest {
        &self.known_good_intent
    }

    /// Record identity assigned to the actual known-good control invocation.
    pub fn known_good_run(&self) -> &EvidenceId {
        &self.known_good_run
    }

    /// Digest of the exact signed planted-violation operation intent.
    pub fn planted_violation_intent(&self) -> &Digest {
        &self.planted_violation_intent
    }

    /// Record identity assigned to the actual planted-violation control invocation.
    pub fn planted_violation_run(&self) -> &EvidenceId {
        &self.planted_violation_run
    }
}

/// The exact result states a control run may report.
///
/// The set is closed and the names are the contract: `docs/03-ONTOLOGY.md`
/// fixes them, and `the_wire_tokens_are_the_ones_the_ontology_fixes` pins the
/// serialized form so a rename here cannot quietly redefine what a stored
/// result meant.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum ControlResult {
    /// The control ran, observed its subject, and found nothing.
    Clean,
    /// The control ran and found what it looks for.
    Violation,
    /// The control did not run.
    NotRun,
    /// The control could not be reached.
    Unavailable,
    /// The control ran but could not decide.
    Unevaluable,
    /// The control ran over a population that should not have been empty.
    UnexpectedlyEmpty,
    /// The control does not apply to this subject.
    NotApplicable,
    /// The control's outcome is not established.
    Unresolved,
}

impl ControlResult {
    /// Every state, in declaration order.
    ///
    /// WHY built through an exhaustive match: a hand-kept list silently omits a
    /// state added later, and the omission is invisible -- the exhaustive-state
    /// test keeps passing while covering one state less, which is precisely the
    /// state nobody has decided how to treat.
    pub fn all() -> Vec<Self> {
        let complete = |result: Self| match result {
            Self::Clean
            | Self::Violation
            | Self::NotRun
            | Self::Unavailable
            | Self::Unevaluable
            | Self::UnexpectedlyEmpty
            | Self::NotApplicable
            | Self::Unresolved => (),
        };
        let states = vec![
            Self::Clean,
            Self::Violation,
            Self::NotRun,
            Self::Unavailable,
            Self::Unevaluable,
            Self::UnexpectedlyEmpty,
            Self::NotApplicable,
            Self::Unresolved,
        ];
        for state in &states {
            complete(*state);
        }
        states
    }
}

/// What a control run was able to observe, against what it was meant to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Coverage {
    /// The subjects the run was meant to observe.
    pub population: u64,
    /// The subjects it did observe.
    pub observed: u64,
}

impl Coverage {
    /// True when the run observed everything it was meant to.
    ///
    /// An empty population is not complete coverage. A control that observed
    /// nothing because there was nothing to observe has established nothing,
    /// and reporting that as full coverage is how an empty population becomes
    /// a clean bill of health.
    pub const fn is_complete(self) -> bool {
        self.population > 0 && self.observed == self.population
    }
}

/// Real-path evidence that an exact control version can fire.
///
/// Both halves are required and neither substitutes for the other: a control
/// that refuses everything refuses the planted violation too, and a control
/// that is never invoked admits the known-good subject just as silently as a
/// working one does.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActivationProof {
    /// This proof's identity as an admitted record.
    pub id: EvidenceId,
    /// The control the proof is about.
    pub control: String,
    /// The exact control version proved.
    pub control_version: String,
    /// Digest of the exact configuration proved.
    pub configuration_digest: Digest,
    /// Policy bundle under which the control was calibrated.
    pub policy: PolicyBundleId,
    /// Digest of the exact policy bytes used during calibration.
    pub policy_digest: Digest,
    /// Digest of the exact adversarial calibration population.
    pub population: Digest,
    /// The mediation path the control was exercised on.
    pub mediation_path: String,
    /// Digest of the known violation planted on that path.
    pub planted_violation: Digest,
    /// What the control reported for it. Must be [`ControlResult::Violation`].
    pub planted_violation_result: ControlResult,
    /// Digest of the known-good subject.
    pub known_good: Digest,
    /// What the control reported for it. Must be [`ControlResult::Clean`].
    pub known_good_result: ControlResult,
    /// The retained evidence of the exercise.
    pub retained_evidence: EvidenceId,
    /// When the proof was produced.
    pub proved_at: Timestamp,
}

/// One control invocation, bound to what it ran against.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ControlRun {
    /// This run's identity as an admitted record.
    pub id: EvidenceId,
    /// The control invoked.
    pub control: String,
    /// The exact control version invoked.
    pub control_version: String,
    /// Digest of the exact configuration invoked.
    pub configuration_digest: Digest,
    /// Policy bundle in force for this invocation.
    pub policy: PolicyBundleId,
    /// Digest of the exact policy bytes in force.
    pub policy_digest: Digest,
    /// Digest of the exact admitted input.
    pub input_digest: Digest,
    /// Digest of the exact subject judged.
    pub subject: Digest,
    /// Digest identifying the exact population the coverage counts describe.
    pub population: Digest,
    /// Digest of the authorization the run was performed under.
    pub authorization: Digest,
    /// The mediation path the run sat on.
    pub mediation_path: String,
    /// When the run began.
    pub started_at: Timestamp,
    /// When the run ended.
    pub finished_at: Timestamp,
    /// The typed result.
    pub result: ControlResult,
    /// What the run observed.
    pub coverage: Coverage,
}

/// An authenticated control run produced under an exact direct grant.
///
/// WHY this wraps [`Admitted<ControlRun>`]: signature admission establishes
/// the producer identity, while the paired direct grant establishes that the
/// producer may run this exact control for this institution at this instant.
#[derive(Clone, Debug)]
pub struct AuthorizedControlRun<'admission> {
    admission: &'admission Admitted<ControlRun>,
    grant: DirectGrant<'admission>,
}

impl<'admission> AuthorizedControlRun<'admission> {
    /// Admit one control run as authorized assurance evidence.
    ///
    /// # Errors
    ///
    /// Returns [`AssuranceAdmissionRefusal`] when the signed record, workspace,
    /// interval, or directly delegated control authority is invalid.
    pub fn admit(
        admission: &'admission Admitted<ControlRun>,
        authority: &'admission Admitted<Delegation>,
        context: &AuthorityContext,
    ) -> Result<Self, AssuranceAdmissionRefusal> {
        check_admission_scope(
            admission.kind(),
            AdmissionKind::ControlRun,
            admission.institution(),
            admission.workspace(),
            context,
        )?;
        let run = admission.payload();
        if run.finished_at < run.started_at {
            return Err(AssuranceAdmissionRefusal::InvertedControlInterval);
        }
        if run.finished_at > context.at() {
            return Err(AssuranceAdmissionRefusal::FutureControlRun);
        }
        let resource = policy_control_resource(&run.control);
        let grant = DirectGrant::admit(
            authority,
            context,
            admission.signer(),
            RUN_POLICY_CONTROL_ACTION,
            &resource,
        )
        .map_err(AssuranceAdmissionRefusal::Authority)?;
        Ok(Self { admission, grant })
    }

    /// The authenticated control-run payload.
    pub fn run(&self) -> &ControlRun {
        self.admission.payload()
    }

    /// The authenticated producer identity.
    pub fn producer(&self) -> &PrincipalId {
        self.admission.signer()
    }

    /// Institution under which the run was admitted.
    pub fn institution(&self) -> &InstitutionId {
        self.admission.institution()
    }

    /// Workspace under which the run was admitted.
    pub fn workspace(&self) -> &InstitutionWorkspaceId {
        self.admission.workspace()
    }

    /// Trusted instant for which its direct grant was resolved.
    pub fn valid_at(&self) -> Timestamp {
        self.grant.valid_at()
    }

    /// Digest of the exact direct owner grant authorizing this run.
    ///
    /// # Errors
    ///
    /// Returns a canonical encoding error if the admitted delegation cannot be
    /// represented canonically.
    pub fn authority_digest(&self) -> Result<Digest, CanonicalError> {
        self.grant.digest()
    }

    /// Latest instant at which the run's direct authority remains live.
    pub fn authority_expires_at(&self) -> Timestamp {
        self.grant.expires_at()
    }
}

/// An authenticated direct owner grant for one exact candidate qualification.
///
/// This is deliberately separate from [`AuthorizedControlRun`]. Permission to
/// produce ordinary control evidence does not authorize the exceptional
/// inactive-generation dispatch needed to establish first activation.
#[derive(Clone, Debug)]
pub struct AuthorizedControlQualification<'admission> {
    grant: DirectGrant<'admission>,
    generation: RuntimeGenerationId,
    policy_digest: Digest,
    binding: String,
    control: String,
    population: Digest,
    vectors: ControlQualificationVectorSet,
}

impl<'admission> AuthorizedControlQualification<'admission> {
    /// Resolve one exact, direct owner-issued qualification grant.
    ///
    /// # Errors
    ///
    /// Returns [`ControlQualificationAuthorityRefusal`] when the grant subject
    /// cannot be encoded or the admitted delegation does not match every exact
    /// authority axis.
    #[expect(
        clippy::too_many_arguments,
        reason = "qualification authority binds independent candidate and control axes"
    )]
    pub fn admit(
        authority: &'admission Admitted<Delegation>,
        context: &AuthorityContext,
        qualification_actor: &PrincipalId,
        generation: RuntimeGenerationId,
        policy_digest: Digest,
        binding: String,
        control: String,
        population: Digest,
        vectors: ControlQualificationVectorSet,
    ) -> Result<Self, ControlQualificationAuthorityRefusal> {
        let resource = policy_control_qualification_resource(
            &generation,
            &policy_digest,
            &binding,
            &control,
            &population,
            &vectors,
        )
        .map_err(ControlQualificationAuthorityRefusal::Canonical)?;
        let grant = DirectGrant::admit(
            authority,
            context,
            qualification_actor,
            QUALIFY_POLICY_CONTROL_ACTION,
            &resource,
        )
        .map_err(ControlQualificationAuthorityRefusal::Authority)?;
        Ok(Self {
            grant,
            generation,
            policy_digest,
            binding,
            control,
            population,
            vectors,
        })
    }

    /// Institution in whose installed authority context this grant resolved.
    pub fn institution(&self) -> &InstitutionId {
        self.grant.admission().institution()
    }

    /// Workspace in whose installed authority context this grant resolved.
    pub fn workspace(&self) -> &InstitutionWorkspaceId {
        self.grant.admission().workspace()
    }

    /// Authenticated actor entrusted with this exact qualification exercise.
    pub fn actor(&self) -> &PrincipalId {
        self.grant.subject()
    }

    /// Candidate generation named by the exact grant resource.
    pub fn generation(&self) -> &RuntimeGenerationId {
        &self.generation
    }

    /// Policy artifact digest named by the exact grant resource.
    pub fn policy_digest(&self) -> &Digest {
        &self.policy_digest
    }

    /// Blocking binding named by the exact grant resource.
    pub fn binding(&self) -> &str {
        &self.binding
    }

    /// Control named by the exact grant resource.
    pub fn control(&self) -> &str {
        &self.control
    }

    /// Immutable good/bad population named by the exact grant resource.
    pub fn population(&self) -> &Digest {
        &self.population
    }

    /// Signed known-good operation intent named by the exact grant resource.
    pub fn known_good_intent(&self) -> &Digest {
        self.vectors.known_good_intent()
    }

    /// Identity reserved for the actual known-good control invocation.
    pub fn known_good_run(&self) -> &EvidenceId {
        self.vectors.known_good_run()
    }

    /// Signed planted-violation operation intent named by the exact grant resource.
    pub fn planted_violation_intent(&self) -> &Digest {
        self.vectors.planted_violation_intent()
    }

    /// Identity reserved for the actual planted-violation control invocation.
    pub fn planted_violation_run(&self) -> &EvidenceId {
        self.vectors.planted_violation_run()
    }

    /// Trusted instant at which the direct grant was resolved.
    pub fn valid_at(&self) -> Timestamp {
        self.grant.valid_at()
    }

    /// Latest instant at which the qualification grant remains live.
    pub fn expires_at(&self) -> Timestamp {
        self.grant.expires_at()
    }

    /// Digest of the exact direct owner grant authorizing qualification.
    ///
    /// # Errors
    ///
    /// Returns a canonical encoding error if the admitted delegation cannot be
    /// represented canonically.
    pub fn authority_digest(&self) -> Result<Digest, CanonicalError> {
        self.grant.digest()
    }

    /// Durable identity of the direct owner grant behind this qualification.
    pub fn authority_id(&self) -> &DelegationId {
        &self.grant.admission().payload().id
    }
}

/// Why a direct grant did not become candidate-qualification authority.
#[derive(Debug)]
#[non_exhaustive]
pub enum ControlQualificationAuthorityRefusal {
    /// The exact resource binding could not be encoded canonically.
    Canonical(CanonicalError),
    /// The admitted delegation was not the required direct owner grant.
    Authority(AuthorityRefusal),
}

impl std::fmt::Display for ControlQualificationAuthorityRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Canonical(error) => {
                write!(formatter, "qualification resource is invalid: {error}")
            }
            Self::Authority(refusal) => {
                write!(formatter, "qualification authority refused: {refusal}")
            }
        }
    }
}

impl std::error::Error for ControlQualificationAuthorityRefusal {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Canonical(error) => Some(error),
            Self::Authority(refusal) => Some(refusal),
        }
    }
}

/// Authenticated activation evidence made by a separately delegated verifier.
#[derive(Clone, Debug)]
pub struct VerifiedActivation<'admission> {
    admission: &'admission Admitted<ActivationProof>,
    grant: DirectGrant<'admission>,
}

impl<'admission> VerifiedActivation<'admission> {
    /// Admit one activation proof under exact verification authority.
    ///
    /// # Errors
    ///
    /// Returns [`AssuranceAdmissionRefusal`] when authentication, scope,
    /// authority, time, or the planted-bad/known-good exercise is invalid.
    pub fn admit(
        admission: &'admission Admitted<ActivationProof>,
        authority: &'admission Admitted<Delegation>,
        context: &AuthorityContext,
    ) -> Result<Self, AssuranceAdmissionRefusal> {
        check_admission_scope(
            admission.kind(),
            AdmissionKind::ActivationProof,
            admission.institution(),
            admission.workspace(),
            context,
        )?;
        let proof = admission.payload();
        if proof.proved_at > context.at() {
            return Err(AssuranceAdmissionRefusal::FutureActivationProof);
        }
        if proof.planted_violation_result != ControlResult::Violation {
            return Err(AssuranceAdmissionRefusal::ActivationDidNotRefuse(
                proof.planted_violation_result,
            ));
        }
        if proof.known_good_result != ControlResult::Clean {
            return Err(AssuranceAdmissionRefusal::ActivationRejectedKnownGood(
                proof.known_good_result,
            ));
        }
        let resource = policy_control_resource(&proof.control);
        let grant = DirectGrant::admit(
            authority,
            context,
            admission.signer(),
            VERIFY_POLICY_CONTROL_ACTION,
            &resource,
        )
        .map_err(AssuranceAdmissionRefusal::Authority)?;
        Ok(Self { admission, grant })
    }

    /// The authenticated activation-proof payload.
    pub fn proof(&self) -> &ActivationProof {
        self.admission.payload()
    }

    /// The authenticated activation verifier identity.
    pub fn verifier(&self) -> &PrincipalId {
        self.admission.signer()
    }

    /// Institution under which the activation was admitted.
    pub fn institution(&self) -> &InstitutionId {
        self.admission.institution()
    }

    /// Workspace under which the activation was admitted.
    pub fn workspace(&self) -> &InstitutionWorkspaceId {
        self.admission.workspace()
    }

    /// Trusted instant for which its direct grant was resolved.
    pub fn valid_at(&self) -> Timestamp {
        self.grant.valid_at()
    }
}

/// Why signed assurance material did not become authorized evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AssuranceAdmissionRefusal {
    /// The consumer-selected admission class differs from the payload role.
    UnexpectedAdmissionKind,
    /// The signed material belongs to another institution.
    ForeignInstitution,
    /// The signed material belongs to another workspace.
    ForeignWorkspace,
    /// The semantic authority grant is invalid.
    Authority(AuthorityRefusal),
    /// A control run ended before it began.
    InvertedControlInterval,
    /// A control run claims to finish after the trusted instant.
    FutureControlRun,
    /// An activation proof claims to exist after the trusted instant.
    FutureActivationProof,
    /// The planted violation did not produce a violation result.
    ActivationDidNotRefuse(ControlResult),
    /// The known-good subject did not produce a clean result.
    ActivationRejectedKnownGood(ControlResult),
}

impl std::fmt::Display for AssuranceAdmissionRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnexpectedAdmissionKind => {
                formatter.write_str("assurance payload was admitted for another use")
            }
            Self::ForeignInstitution => {
                formatter.write_str("assurance payload belongs to another institution")
            }
            Self::ForeignWorkspace => {
                formatter.write_str("assurance payload belongs to another workspace")
            }
            Self::Authority(refusal) => write!(formatter, "assurance authority refused: {refusal}"),
            Self::InvertedControlInterval => {
                formatter.write_str("control run ended before it began")
            }
            Self::FutureControlRun => {
                formatter.write_str("control run finishes after the trusted instant")
            }
            Self::FutureActivationProof => {
                formatter.write_str("activation proof postdates the trusted instant")
            }
            Self::ActivationDidNotRefuse(result) => write!(
                formatter,
                "planted violation produced {result:?} rather than violation"
            ),
            Self::ActivationRejectedKnownGood(result) => write!(
                formatter,
                "known-good subject produced {result:?} rather than clean"
            ),
        }
    }
}

impl std::error::Error for AssuranceAdmissionRefusal {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Authority(refusal) => Some(refusal),
            _ => None,
        }
    }
}

fn check_admission_scope(
    found: AdmissionKind,
    expected: AdmissionKind,
    institution: &InstitutionId,
    workspace: &InstitutionWorkspaceId,
    context: &AuthorityContext,
) -> Result<(), AssuranceAdmissionRefusal> {
    if found != expected {
        return Err(AssuranceAdmissionRefusal::UnexpectedAdmissionKind);
    }
    if institution != context.institution() {
        return Err(AssuranceAdmissionRefusal::ForeignInstitution);
    }
    if workspace != context.workspace() {
        return Err(AssuranceAdmissionRefusal::ForeignWorkspace);
    }
    Ok(())
}

/// Why a set of runs does not support a clean claim.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClaimRefusal {
    /// No run judged this subject.
    NoRun,
    /// The same control ran more than once over the same input and subject.
    ///
    /// WHY this refuses rather than choosing: with two results in hand the
    /// tempting move is to take the clean one, and that is precisely the move
    /// that turns a flaky or bypassed control into a passing claim.
    DuplicateInvocation {
        /// The control invoked twice.
        control: String,
    },
    /// The run reported something other than clean.
    ResultNotClean(ControlResult),
    /// The run did not observe everything it was meant to.
    PartialCoverage {
        /// What it observed.
        observed: u64,
        /// What it was meant to observe.
        population: u64,
    },
    /// The run observed nothing because there was nothing to observe.
    EmptyPopulation,
    /// The run ended before it began.
    InvertedInterval,
    /// Run and activation were admitted for different institution workspaces.
    AdmissionScopeMismatch,
    /// Run and activation authority were resolved at different trusted instants.
    AuthorityTimeMismatch,
    /// The control producer also vouched for its own activation.
    SelfAttestedActivation,
    /// The activation proof was produced after the control invocation began.
    ActivationAfterRun,
    /// The activation proof is about a different control.
    ActivationControlMismatch,
    /// The activation proof is about a different control version.
    ActivationVersionMismatch,
    /// The activation proof is about a different configuration.
    ActivationConfigurationMismatch,
    /// The activation proof exercised a different mediation path.
    ActivationPathMismatch,
    /// The planted violation did not produce a refusal.
    ActivationDidNotRefuse(ControlResult),
    /// The known-good subject was not admitted.
    ActivationRejectedKnownGood(ControlResult),
}

impl std::fmt::Display for ClaimRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClaimRefusal::NoRun => formatter.write_str("no control run judged this subject"),
            ClaimRefusal::DuplicateInvocation { control } => write!(
                formatter,
                "control {control} ran more than once over the same input and subject"
            ),
            ClaimRefusal::ResultNotClean(result) => {
                write!(formatter, "the control reported {result:?}, not clean")
            }
            ClaimRefusal::PartialCoverage {
                observed,
                population,
            } => write!(
                formatter,
                "the control observed {observed} of {population} subjects"
            ),
            ClaimRefusal::EmptyPopulation => {
                formatter.write_str("the control observed an empty population")
            }
            ClaimRefusal::InvertedInterval => {
                formatter.write_str("the control run ended before it began")
            }
            ClaimRefusal::AdmissionScopeMismatch => {
                formatter.write_str("control run and activation belong to different workspaces")
            }
            ClaimRefusal::AuthorityTimeMismatch => formatter.write_str(
                "control run and activation authority were resolved at different instants",
            ),
            ClaimRefusal::SelfAttestedActivation => {
                formatter.write_str("the control producer also signed its activation proof")
            }
            ClaimRefusal::ActivationAfterRun => {
                formatter.write_str("the activation proof postdates the control invocation")
            }
            ClaimRefusal::ActivationControlMismatch => {
                formatter.write_str("the activation proof is about a different control")
            }
            ClaimRefusal::ActivationVersionMismatch => {
                formatter.write_str("the activation proof is about a different control version")
            }
            ClaimRefusal::ActivationConfigurationMismatch => {
                formatter.write_str("the activation proof is about a different configuration")
            }
            ClaimRefusal::ActivationPathMismatch => {
                formatter.write_str("the activation proof exercised a different mediation path")
            }
            ClaimRefusal::ActivationDidNotRefuse(result) => write!(
                formatter,
                "the planted violation produced {result:?} rather than a refusal"
            ),
            ClaimRefusal::ActivationRejectedKnownGood(result) => write!(
                formatter,
                "the known-good subject produced {result:?} rather than clean"
            ),
        }
    }
}

impl std::error::Error for ClaimRefusal {}

/// The one route to a clean assurance claim.
///
/// Every check here is a way the claim fails; there is no other way for it to
/// succeed. That is deliberate and is the module's whole shape: an adapter
/// cannot reach a clean claim by any path except a run whose result is
/// literally [`ControlResult::Clean`], over complete coverage, with an
/// activation proof binding the same control version, configuration and
/// mediation path, and showing both that the planted violation was refused and
/// that the known-good subject was admitted.
///
/// WHY the claim names one control rather than judging a subject in general:
/// several controls may judge one subject, and a function that took only the
/// subject would have to choose among their runs. Any choice is arbitrary and
/// order-dependent, and the tempting one -- the first clean result -- is the
/// bug. An assurance case is built claim by claim, one control at a time, so
/// the signature says so.
///
/// # Errors
///
/// Returns the first [`ClaimRefusal`] that applies. Checks run from the cheapest
/// and most specific outward, so the reported reason is the one nearest to what
/// the caller controls.
///
/// Time: O(n) for n runs. Space: O(1).
pub fn clean_claim<'run>(
    runs: &'run [AuthorizedControlRun<'_>],
    control: &str,
    subject: &Digest,
    activation: &VerifiedActivation<'_>,
) -> Result<&'run ControlRun, ClaimRefusal> {
    let mut judged = runs.iter().filter(|admitted| {
        let run = admitted.run();
        run.control == control && &run.subject == subject
    });

    let Some(admitted_run) = judged.next() else {
        return Err(ClaimRefusal::NoRun);
    };
    // WHY any second run refuses, whatever it says: two invocations of one
    // control over one subject leave nothing saying which is authoritative.
    // Agreement does not help -- it is also what a control returning a
    // constant produces -- and disagreement is where taking the clean one
    // turns a flaky or partly-bypassed control into a passing claim.
    if judged.next().is_some() {
        return Err(ClaimRefusal::DuplicateInvocation {
            control: control.to_string(),
        });
    }
    let run = admitted_run.run();
    let activation_proof = activation.proof();

    if admitted_run.institution() != activation.institution()
        || admitted_run.workspace() != activation.workspace()
    {
        return Err(ClaimRefusal::AdmissionScopeMismatch);
    }
    if admitted_run.valid_at() != activation.valid_at() {
        return Err(ClaimRefusal::AuthorityTimeMismatch);
    }
    if admitted_run.producer() == activation.verifier() {
        return Err(ClaimRefusal::SelfAttestedActivation);
    }
    if activation_proof.proved_at > run.started_at {
        return Err(ClaimRefusal::ActivationAfterRun);
    }

    // The exhaustive match is the point. A state added later has no arm and the
    // build stops, rather than the new state falling through to whichever
    // branch a boolean projection would have put it in.
    match run.result {
        ControlResult::Clean => {}
        other @ (ControlResult::Violation
        | ControlResult::NotRun
        | ControlResult::Unavailable
        | ControlResult::Unevaluable
        | ControlResult::UnexpectedlyEmpty
        | ControlResult::NotApplicable
        | ControlResult::Unresolved) => return Err(ClaimRefusal::ResultNotClean(other)),
    }

    if run.finished_at < run.started_at {
        return Err(ClaimRefusal::InvertedInterval);
    }
    if run.coverage.population == 0 {
        return Err(ClaimRefusal::EmptyPopulation);
    }
    if !run.coverage.is_complete() {
        return Err(ClaimRefusal::PartialCoverage {
            observed: run.coverage.observed,
            population: run.coverage.population,
        });
    }

    if activation_proof.control != run.control {
        return Err(ClaimRefusal::ActivationControlMismatch);
    }
    if activation_proof.control_version != run.control_version {
        return Err(ClaimRefusal::ActivationVersionMismatch);
    }
    if activation_proof.configuration_digest != run.configuration_digest {
        return Err(ClaimRefusal::ActivationConfigurationMismatch);
    }
    if activation_proof.mediation_path != run.mediation_path {
        return Err(ClaimRefusal::ActivationPathMismatch);
    }
    if activation_proof.planted_violation_result != ControlResult::Violation {
        return Err(ClaimRefusal::ActivationDidNotRefuse(
            activation_proof.planted_violation_result,
        ));
    }
    if activation_proof.known_good_result != ControlResult::Clean {
        return Err(ClaimRefusal::ActivationRejectedKnownGood(
            activation_proof.known_good_result,
        ));
    }

    Ok(run)
}
