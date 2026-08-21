//! Do the pieces compose?
//!
//! Every module in this workspace tests itself. Nothing tests that they fit
//! together, and that is a distinct claim: each module can be correct against
//! its own fixtures while the identities it produces are not the ones its
//! neighbour expects. `crates/politeiad`'s exit criteria is the complete
//! `docs/18-FIRST_VERTICAL_SLICE.md` path under adversarial tests; this is the
//! spine of it, over in-memory pieces.
//!
//! WHAT IT DOES NOT COVER, said plainly because a composition test invites the
//! assumption that it covers everything it touches:
//!
//! - Specialization and activation. Deriving a `RuntimeGeneration` needs a
//!   workspace, commissioning record, grant registry and evidence registry,
//!   and that fixture is `pub(crate)` inside `politeia-core` — reachable by its
//!   own tests and not from here. Exposing it publicly to reach it would put a
//!   test fixture in the product's API.
//! - The dispatcher and effect path. `politeia-runtime` is not a dependency
//!   here; its own tests cover lease issue, replay and audience binding.
//! - Anything durable. Every store here is in-memory, which
//!   `docs/09-PERSISTENCE.md` sanctions for deterministic tests and not for
//!   the deployment evidence `docs/18` separately requires.

use std::collections::{BTreeMap, BTreeSet};

use jiff::{SignedDuration, Timestamp};
use politeia_core::institution::InstitutionBoundary;
use politeia_core::journal::{TransitionEntry, TransitionJournal, verify_chain};
use politeia_core::knowledge::{CandidateClaim, ClaimStatus, FactApproval, Observation, approve};
use politeia_core::outbox::{
    BoundaryCrossing, DenialReason, OutboxDeclaration, Sink, SinkKind, adjudicate,
};
use politeia_core::reconnaissance::{RECONNOITRE_ACTION, ReconnaissanceScope};
use politeia_core::{
    AdapterId, DataClass, Delegation, DelegationId, Digest, Effect, EvidenceId, ExecutionLocality,
    InstitutionId, InstitutionWorkspaceId, ObservationId, OperationId, PolicyBundleId, PrincipalId,
    ResourceBudget, RuntimeGenerationId,
};
use politeia_evidence::{Attestation, IndependenceClass, Verification};

const SOURCE: &str = "crm";
const SINK: &str = "inference:acme";

fn at() -> Timestamp {
    "2026-08-21T00:00:00Z"
        .parse()
        .unwrap_or_else(|_| unreachable!("the fixture timestamp is valid RFC 3339"))
}

fn trust_domain() -> politeia_core::institution::TrustDomainId {
    "client-a:production"
        .parse()
        .unwrap_or_else(|_| unreachable!("the fixture trust domain is canonical"))
}

fn declaration() -> OutboxDeclaration {
    OutboxDeclaration {
        sinks: BTreeMap::from([(
            SINK.to_string(),
            Sink {
                kind: SinkKind::RemoteInferenceProvider,
                identity: SINK.to_string(),
                locality: ExecutionLocality::ProviderRemote,
            },
        )]),
        purposes: BTreeSet::from(["answer a support question".to_string()]),
        retention_rules: BTreeSet::from(["delete-after-30-days".to_string()]),
        commissioner_export: BTreeSet::new(),
    }
}

struct Slice {
    boundary: InstitutionBoundary<OutboxDeclaration>,
    commissioner: PrincipalId,
    owner: PrincipalId,
    scope: ReconnaissanceScope,
    delegation: Delegation,
    adapter: AdapterId,
}

fn slice() -> Slice {
    let workspace = InstitutionWorkspaceId::new();
    let commissioner = PrincipalId::new();
    let owner = PrincipalId::new();
    let adapter = AdapterId::new();
    let delegation_id = DelegationId::new();

    Slice {
        boundary: InstitutionBoundary::new(InstitutionId::new(), workspace, declaration()),
        scope: ReconnaissanceScope {
            commissioner: commissioner.clone(),
            delegation: delegation_id.clone(),
            sources: BTreeSet::from([SOURCE.to_string()]),
            adapters: BTreeSet::from([adapter.clone()]),
            expires_at: at() + SignedDuration::from_hours(4),
        },
        delegation: Delegation {
            id: delegation_id,
            issuer: owner.clone(),
            subject: commissioner.clone(),
            parent: None,
            actions: BTreeSet::from([RECONNOITRE_ACTION.to_string()]),
            resources: BTreeSet::from(["crm:contacts".to_string()]),
            effects: BTreeSet::from([Effect::ReadExternalSystem]),
            data_classes: BTreeSet::from([DataClass::Internal]),
            audience: BTreeSet::from(["commissioning".to_string()]),
            expires_at: at() + SignedDuration::from_hours(4),
            budget: ResourceBudget {
                wall_ms: Some(1),
                cpu_ms: Some(1),
                memory_bytes: Some(1),
                io_bytes: Some(1),
                network_bytes: Some(1),
                external_cost_microunits: Some(1),
            },
        },
        commissioner,
        owner,
        adapter,
    }
}

fn observation(s: &Slice, statement: &[u8]) -> Observation {
    Observation {
        id: ObservationId::new(),
        workspace: s.boundary.workspace().clone(),
        source: SOURCE.to_string(),
        adapter: s.adapter.clone(),
        subject: Digest::blake3(b"the institution's billing contact"),
        statement: Digest::blake3(statement),
        observed_at: at(),
        evidence: EvidenceId::new(),
    }
}

/// The path: observe, interpret, approve, journal, publish, attest.
#[test]
fn one_bounded_path_runs_end_to_end() {
    let s = slice();

    // 1. Bounded reconnaissance admits an observation.
    let seen = observation(&s, b"finance handles billing");
    assert_eq!(
        s.scope.admit(&s.boundary, &s.delegation, &seen, at()),
        Ok(()),
        "an in-scope observation is admitted"
    );

    // 2. Interpretation produces a candidate, uncontested.
    let claim = CandidateClaim {
        id: politeia_core::ClaimId::new(),
        subject: seen.subject.clone(),
        proposition: Digest::blake3(b"billing is handled by the finance team"),
        supported_by: BTreeMap::from([(SOURCE.to_string(), BTreeSet::from([seen.id.clone()]))]),
        contradicted_by: BTreeMap::new(),
        missed_axes: BTreeSet::from(["subsidiaries".to_string()]),
        interpreter: s.commissioner.clone(),
        interpreter_delegation: s.delegation.id.clone(),
    };
    assert_eq!(claim.status(), ClaimStatus::Candidate);

    // 3. The owner approves it, acknowledging the gap it declares.
    let fact = approve(
        &claim,
        &FactApproval {
            claim: claim.id.clone(),
            proposition: claim.proposition.clone(),
            acknowledged_status: claim.status(),
            acknowledged_missed_axes: BTreeSet::from(["subsidiaries".to_string()]),
            owner: s.owner.clone(),
            owner_delegation: DelegationId::new(),
            approved_at: at(),
        },
    )
    .unwrap_or_else(|refusal| unreachable!("the candidate is approvable: {refusal}"));
    assert_eq!(
        fact.accepted_gaps(),
        &BTreeSet::from(["subsidiaries".to_string()]),
        "the gap travels with the fact rather than being dropped at approval"
    );

    // 4. The transition is journalled, binding the authority behind it.
    let mut journal = TransitionJournal::for_boundary(&s.boundary);
    let recorded = journal
        .append(TransitionEntry {
            workspace: s.boundary.workspace().clone(),
            trust_domain: trust_domain(),
            actor: s.owner.clone(),
            delegation: DelegationId::new(),
            operation: OperationId::new(),
            before: None,
            after: Some(fact.proposition().clone()),
            policy_bundle: PolicyBundleId::new(),
            policy_digest: Digest::blake3(b"policy"),
            runtime: RuntimeGenerationId::derive(b"generation"),
            execution_resource: None,
            routing_decision: None,
            adapter: Some(s.adapter.clone()),
            evidence: BTreeSet::from([seen.evidence.clone()]),
            at: at(),
        })
        .unwrap_or_else(|refusal| unreachable!("the entry belongs here: {refusal}"))
        .digest()
        .clone();
    assert_eq!(journal.head(), Some(&recorded));
    assert_eq!(journal.verify(), Ok(()));

    // 5. Publishing the derived fact crosses the boundary, and is recorded.
    let crossing = BoundaryCrossing {
        workspace: s.boundary.workspace().clone(),
        purpose: "answer a support question".to_string(),
        source: SOURCE.to_string(),
        transformation: "approved fact".to_string(),
        sink: SINK.to_string(),
        data_classes: BTreeSet::from([DataClass::Internal]),
        retention_rule: "delete-after-30-days".to_string(),
        execution_resource: None,
        routing_decision: None,
        authority: s.owner.clone(),
        authority_delegation: DelegationId::new(),
        subject: fact.subject().clone(),
        at: at(),
    };
    let adjudication = adjudicate(&s.boundary, &crossing);
    assert!(
        adjudication.allowed(),
        "a fully declared crossing is allowed"
    );

    // 6. An independent verifier attests the result, bound to this subject.
    let verification = Verification {
        subject: fact.subject().clone(),
        verifier: PrincipalId::new(),
        evidence: vec![seen.evidence.clone()],
        passed: true,
        independence: IndependenceClass::IndependentService,
    };
    let attestation = Attestation::issue(
        &verification,
        &s.commissioner,
        PolicyBundleId::new(),
        RuntimeGenerationId::derive(b"generation"),
        s.adapter.clone(),
        s.delegation.id.clone(),
    )
    .unwrap_or_else(|refusal| {
        unreachable!("an independent passing verification attests: {refusal}")
    });

    assert!(
        attestation.covers(fact.subject()),
        "the attestation is about the subject the path actually produced"
    );
}

/// The same path, with one foreign identity introduced at each hop.
///
/// A happy path alone shows that the pieces can agree. What matters is that
/// they cannot be made to disagree — that every stage asks the same boundary
/// whose institution this is, rather than each carrying an answer.
#[test]
fn foreign_material_is_refused_at_every_hop() {
    let s = slice();
    let theirs = InstitutionWorkspaceId::new();

    let mut foreign_observation = observation(&s, b"their billing contact");
    foreign_observation.workspace = theirs.clone();
    assert!(
        s.scope
            .admit(&s.boundary, &s.delegation, &foreign_observation, at())
            .is_err(),
        "reconnaissance refuses another institution's observation"
    );

    let mut journal = TransitionJournal::for_boundary(&s.boundary);
    let foreign_entry = TransitionEntry {
        workspace: theirs.clone(),
        trust_domain: trust_domain(),
        actor: s.owner.clone(),
        delegation: DelegationId::new(),
        operation: OperationId::new(),
        before: None,
        after: None,
        policy_bundle: PolicyBundleId::new(),
        policy_digest: Digest::blake3(b"policy"),
        runtime: RuntimeGenerationId::derive(b"generation"),
        execution_resource: None,
        routing_decision: None,
        adapter: None,
        evidence: BTreeSet::new(),
        at: at(),
    };
    assert!(
        journal.append(foreign_entry).is_err(),
        "the journal refuses another institution's transition"
    );
    assert!(journal.entries().is_empty());

    let mut foreign_crossing = BoundaryCrossing {
        workspace: theirs,
        purpose: "answer a support question".to_string(),
        source: SOURCE.to_string(),
        transformation: "approved fact".to_string(),
        sink: SINK.to_string(),
        data_classes: BTreeSet::from([DataClass::Internal]),
        retention_rule: "delete-after-30-days".to_string(),
        execution_resource: None,
        routing_decision: None,
        authority: s.owner.clone(),
        authority_delegation: DelegationId::new(),
        subject: Digest::blake3(b"their fact"),
        at: at(),
    };
    let adjudication = adjudicate(&s.boundary, &foreign_crossing);
    assert_eq!(adjudication.denied, Some(DenialReason::ForeignWorkspace));
    assert_eq!(
        adjudication.crossing.workspace, foreign_crossing.workspace,
        "the refusal is recorded rather than discarded"
    );

    // And the same crossing, corrected to this institution, is allowed --
    // so the refusal above was about ownership and not about something else
    // the fixture happened to get wrong.
    foreign_crossing.workspace = s.boundary.workspace().clone();
    assert!(adjudicate(&s.boundary, &foreign_crossing).allowed());
}

/// A journal that has been edited does not verify, whatever else still holds.
#[test]
fn an_edited_journal_is_detectable_after_the_fact() {
    let s = slice();
    let mut journal = TransitionJournal::for_boundary(&s.boundary);
    for index in 0..3u8 {
        let entry = TransitionEntry {
            workspace: s.boundary.workspace().clone(),
            trust_domain: trust_domain(),
            actor: s.owner.clone(),
            delegation: DelegationId::new(),
            operation: OperationId::new(),
            before: None,
            after: Some(Digest::blake3(&[index])),
            policy_bundle: PolicyBundleId::new(),
            policy_digest: Digest::blake3(b"policy"),
            runtime: RuntimeGenerationId::derive(b"generation"),
            execution_resource: None,
            routing_decision: None,
            adapter: None,
            evidence: BTreeSet::new(),
            at: at(),
        };
        assert!(journal.append(entry).is_ok());
    }
    assert_eq!(journal.verify(), Ok(()));

    let mut without_the_middle = journal.entries().to_vec();
    without_the_middle.remove(1);
    assert!(
        verify_chain(&without_the_middle).is_err(),
        "every remaining entry still matches its own digest; the sequence does not"
    );
}
