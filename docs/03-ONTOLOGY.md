# Canonical ontology

The ontology is the durable semantic center. Transports and UIs project it; they do not redefine it.

## Identity

- `Principal`: actor capable of requesting work.
- `Institution`: authority domain whose approved model and workspace are distinct from every other institution.
- `TrustDomain`: boundary that controls data, credentials, execution, evidence, and durable state.
- `Delegation`: attenuation from one authority context to another.
- `Resource`: protected object or resource set.
- `Action`: semantic operation over resources.
- `Artifact`: content-addressable subject of work or evidence.
- `RuntimeGeneration`: immutable, content-bound specialization of canonical source + institution workspace + approved policy + lifecycle profile + deployment topology + exact schemas, packs, adapters, and toolchain inputs.
- `PolicyBundle`: immutable policy identity.

## Institutional roles

- `InstitutionOwner`: principal or authority set entitled to establish or alter constitutional commitments; not synonymous with system administrator.
- `Commissioner`: temporarily delegated principal that may discover, model, implement, and prepare an institution for operation. Its authority is explicit, scoped, expiring/revocable, and never self-issued.
- `Maintainer`: principal delegated bounded post-handoff maintenance or recommissioning work.
- `Worker`: principal or execution resource performing bounded work.
- `Verifier`: principal or service assigned an assurance obligation. Independence derives from the obligation and control relationship, not this label.

A role describes a relationship. It never creates ambient authority; a protected effect still requires an exact delegation and authorization.

## Institutional knowledge

- `Observation`: sourced statement about reality.
- `Claim`: interpreted proposition with confidence and provenance.
- `ContestedClaim`: claim with unresolved contradiction.
- `ApprovedFact`: institutionally accepted fact.
- `Requirement`: condition expected to hold.
- `Preference`: defeasible choice among valid alternatives.
- `ConstitutionalCommitment`: commitment whose weakening requires elevated authority.

## Governance

- `NormativeClause`: proposition about what must/may/must-not be true.
- `DetectorSpec`: mechanism that produces evidence relevant to a clause.
- `PolicyBinding`: applicability + detector/evidence semantics + decision consequence.
- `Finding`: evidence-backed nonconformance or concern.
- `Waiver`: authorized scoped permission for nonconformance.
- `PolicyDecision`: normalized authorization/governance result.

## Work

- `Intent`: desired outcome.
- `Task`: bounded unit of work.
- `Plan`: dependency-aware decomposition of intent.
- `Workflow`: legal state transitions plus operations.
- `OperationSpec`: typed operation contract.
- `EffectSet`: declared externally visible effects.
- `ResourceBudget`: bounded consumption and cost.
- `Transition`: state change with preconditions and evidence obligations.
- `ExecutionResource`: model, deterministic tool, human, or service capable of bounded work.
- `CapabilityProfile`: evidence-backed description of what an exact execution resource has demonstrated under named conditions.
- `ExecutionRequirement`: hard constraints and ordered soft preferences for selecting a worker.
- `RoutingDecision`: provenance-bearing selection or escalation that explains hard eligibility, soft comparison, and verification obligations. It is not an authorization.
- `EffectSubject`: canonical identity derived from the target, resolved operation, resource set, and
  effect-defining parameters. Equivalent or uncertainly overlapping effects must not evade replay
  checks through fresh local identifiers or alternate encodings.
- `ExecutionEnvelope`: immutable cross-context request/authorization carrier binding the exact
  request-body and resolved `OperationSpec` digests, intent, effect subject, authority,
  policy/runtime identities, intended target audience and resource/adapter identities,
  operation-specific precondition contract and evaluation, replay contract, expiry, and evidence
  obligations. It is neither an effect lease nor evidence that execution occurred.
- `EnvelopeAdmission`: opaque, single-use target-side record binding the validated envelope digest
  and effect subject to the exclusively derived local intent, current authorization/replay
  evaluation, and local lease reservation. It cannot widen or replace envelope authority.
- `ExecutionReceipt`: evidence about target-side execution bound to the exact envelope admission,
  local lease/reservation, executor/resource, environment, results, and evidence. It cannot
  retroactively create missing authority.
- `DeliveryState`: observed progress of issuing, transferring, acknowledging, and returning an envelope or receipt.
- `ExecutionOutcome`: target-side semantic result value such as `succeeded`, `failed`,
  `partially_applied`, or `not_executed`. It carries no confidence or finality; those belong to
  epistemic resolution. The absence of an outcome is not itself an outcome.
- `EpistemicResolution`: what admitted evidence establishes about whether the effect executed and
  the confidence/finality of any outcome. Unresolved knowledge is not a failed or not-executed
  outcome.
- `ReplayPolicy`: conditions under which an overlapping effect subject may repeat, must deduplicate at a proven target boundary, requires compensation, or must remain blocked.
- `ReplayDisposition`: current typed decision for an overlapping effect subject, kept separate from both the static replay policy and the execution outcome.
- `ExecutionAssessment`: evidence-bearing record that binds, without collapsing, the applicable
  delivery state, optional execution outcome, epistemic resolution, replay disposition, and
  supporting evidence.
- `SemanticClosure`: non-authorizing, transport-independent resolution path attached to a surfaced
  gap. It references existing semantic operations and preflight requirements; it does not create a
  second intent model.

## Commissioning and specialization

- `InstitutionWorkspace`: institution-owned semantic input boundary for its approved model, private extensions, policies, tests, generation inputs, and secret references (never secret values).
- `LifecycleProfile`: authority/capability posture: bootstrap, commissioning, operational, maintenance, or recommissioning.
- `DeploymentTopology`: placement and assurance posture such as local development, client-controlled single-tenant, or high-assurance isolation.
- `CommissioningRecord`: provenance chain from observations through owner approvals to exact approved specialization inputs and a generation candidate.
- `HandoffReceipt`: post-activation record binding the operational generation, commissioner revocation, client acceptance, and continuity evidence.

Lifecycle and topology are independent axes. A runtime generation binds both; neither may silently redefine semantic meaning.

## Assurance

- `Evidence`: provenance-bearing observation admitted for a claim.
- `Verification`: independent or designated evaluation of evidence/subject.
- `Attestation`: durable statement binding subject, evaluator, policy, runtime, and evidence.
- `EvidenceObligation`: required evidence class for a transition or binding.
- `ControlResult`: evidence-bearing result with the exact states `clean`, `violation`, `not_run`, `unavailable`, `unevaluable`, `unexpectedly_empty`, `not_applicable`, and `unresolved`.
- `ActivationProof`: real-path evidence that an exact control version can observe and produce its promised refusal or finding for a known violation while admitting a clean control.
- `Correction`: append-only evidence that amends the interpretation of an immutable delivered or attested subject.
- `Supersession`: relation selecting a newer artifact or assessment for future use while preserving the prior subject.
- `AssessmentEvent`: provenance-bearing observation, assessment, correction, supersession, or verdict change used where historical interpretation matters.
- `CurrentAssessment`: reproducible projection over the admitted assessment events, criterion
  version, and deterministic correction/supersession conflict rules. Competing live successors
  remain unresolved.

## Learning

- `Observation` → `Finding` → `Lesson` → `Proposal` → approved change → stronger projection/enforcement.

No subsystem may mint a second concept for the same semantics merely for convenience.
