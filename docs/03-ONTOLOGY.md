# Canonical ontology

The ontology is the durable semantic center. Transports and UIs project it; they do not redefine it.

## Identity

- `Principal`: actor capable of requesting work.
- `Delegation`: attenuation from one authority context to another.
- `Resource`: protected object or resource set.
- `Action`: semantic operation over resources.
- `Artifact`: content-addressable subject of work or evidence.
- `RuntimeGeneration`: immutable executable + policy + schema + trusted pack/adapters set.
- `PolicyBundle`: immutable policy identity.

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

## Assurance

- `Evidence`: provenance-bearing observation admitted for a claim.
- `Verification`: independent or designated evaluation of evidence/subject.
- `Attestation`: durable statement binding subject, evaluator, policy, runtime, and evidence.
- `EvidenceObligation`: required evidence class for a transition or binding.

## Learning

- `Observation` → `Finding` → `Lesson` → `Proposal` → approved change → stronger projection/enforcement.

No subsystem may mint a second concept for the same semantics merely for convenience.
