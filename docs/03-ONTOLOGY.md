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

## Learning

- `Observation` → `Finding` → `Lesson` → `Proposal` → approved change → stronger projection/enforcement.

No subsystem may mint a second concept for the same semantics merely for convenience.
