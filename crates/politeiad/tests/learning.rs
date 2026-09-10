#![expect(
    clippy::expect_used,
    reason = "authenticated fixture construction must fail loudly when its canonical chain drifts"
)]

#[path = "../src/learning.rs"]
mod learning;

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::SigningKey;
use jiff::Timestamp;
use learning::*;
use politeia_core::{
    AdapterId, ClaimId, DataClass, Delegation, DelegationId, Digest, EvidenceId, InstitutionId,
    InstitutionWorkspaceId, ObservationId, PolicyBundleId, PrincipalId, ResourceBudget,
    RuntimeGenerationId, SourceCaptureId,
    evidence::{EvidenceRecord, IndependenceClass, TrustedEvidenceRegistry},
    generation::{ApprovedGenerationInputs, ReproducibilityContract},
    institution::{InstitutionWorkspace, TrustDomainId},
    knowledge::{
        CandidateClaimRequest, ClaimStatus, FactApprovalRequest, Observation,
        TrustedCandidateClaimRegistry, TrustedObservationRegistry, approve_claim,
        candidate_claim_digest,
    },
    lifecycle::{DeploymentTopology, LifecycleProfile},
    trust::{AdmissionKind, InstitutionTrustAnchors, SignedAdmissionWire, TrustedSigningKey},
};
use politeia_evidence::assessment::{AssessmentRelation, Projection, RelationKind, Unresolved};

#[expect(
    clippy::expect_used,
    reason = "fixed test fixtures must fail loudly if their authenticated chain drifts"
)]
fn at() -> Timestamp {
    "2026-09-09T00:00:00Z".parse().expect("valid timestamp")
}

fn budget() -> ResourceBudget {
    ResourceBudget {
        wall_ms: None,
        cpu_ms: None,
        memory_bytes: None,
        io_bytes: None,
        network_bytes: None,
        external_cost_microunits: None,
    }
}

fn workspace() -> InstitutionWorkspace {
    InstitutionWorkspace {
        id: InstitutionWorkspaceId::new(),
        institution: InstitutionId::new(),
        trust_domain: "client:learning"
            .parse::<TrustDomainId>()
            .expect("canonical trust domain"),
        owner: PrincipalId::new(),
        owner_delegation: DelegationId::new(),
        approved_model_digest: Digest::blake3(b"model"),
        policy_bundle: PolicyBundleId::new(),
        policy_digest: Digest::blake3(b"policy"),
        approved_generation: ApprovedGenerationInputs {
            source_digest: Digest::blake3(b"source"),
            lifecycle: LifecycleProfile::Commissioning,
            topology: DeploymentTopology::ClientControlledSingleTenant,
            schema_digests: BTreeMap::new(),
            adapter_digests: BTreeMap::new(),
            pack_digests: BTreeMap::new(),
            component_digests: BTreeMap::new(),
            excluded_commissioning_capabilities: BTreeSet::new(),
            specializer_digest: Digest::blake3(b"specializer"),
            toolchain_digest: Digest::blake3(b"toolchain"),
            reproducibility: ReproducibilityContract::Deterministic,
        },
        secret_references: BTreeSet::new(),
    }
}

#[expect(
    clippy::expect_used,
    reason = "fact fixture must traverse canonical approval"
)]
fn approved_fact(
    workspace: &InstitutionWorkspace,
    source: &str,
) -> politeia_core::knowledge::ApprovedFact {
    let key = SigningKey::from_bytes(&[19; 32]);
    let subject = Digest::blake3(b"billing");
    let observation = Observation {
        id: ObservationId::new(),
        capture: SourceCaptureId::new(),
        capture_manifest_digest: Digest::blake3(b"learning capture manifest"),
        workspace: workspace.id.clone(),
        source: source.to_string(),
        adapter: AdapterId::new(),
        subject: subject.clone(),
        statement: Digest::blake3(source.as_bytes()),
        observed_at: at(),
        evidence: EvidenceId::new(),
    };
    let evidence = TrustedEvidenceRegistry::from_trusted_bootstrap([EvidenceRecord {
        id: observation.evidence.clone(),
        subject: subject.clone(),
        producer: workspace.owner.clone(),
        producer_delegation: workspace.owner_delegation.clone(),
        method: "fixture".to_string(),
        payload_digest: Digest::blake3(b"payload"),
        observed_at: at(),
        independence: IndependenceClass::HumanAuthority,
    }])
    .expect("unique evidence");
    let observations = TrustedObservationRegistry::from_trusted_bootstrap(
        &workspace.id,
        &evidence,
        [observation.clone()],
    )
    .expect("bound observation");
    let claim = CandidateClaimRequest {
        id: ClaimId::new(),
        workspace: workspace.id.clone(),
        subject: subject.clone(),
        proposition: Digest::blake3(b"finance"),
        supported_by: BTreeMap::from([(
            source.to_string(),
            BTreeSet::from([observation.id.clone()]),
        )]),
        contradicted_by: BTreeMap::new(),
        missed_axes: BTreeSet::new(),
        interpreter: workspace.owner.clone(),
        interpreter_delegation: workspace.owner_delegation.clone(),
    };
    let anchors = InstitutionTrustAnchors::from_trusted_bootstrap(
        workspace.institution.clone(),
        workspace.id.clone(),
        [TrustedSigningKey::new(
            workspace.owner.clone(),
            key.verifying_key().to_bytes(),
            BTreeSet::from([AdmissionKind::CandidateClaim, AdmissionKind::FactApproval]),
        )
        .expect("valid key")],
    )
    .expect("one owner");
    let candidates = TrustedCandidateClaimRegistry::admit_signed(
        workspace,
        &anchors,
        &observations,
        [SignedAdmissionWire::sign(
            AdmissionKind::CandidateClaim,
            workspace.institution.clone(),
            workspace.id.clone(),
            workspace.owner.clone(),
            claim.clone(),
            &key,
        )
        .expect("signed candidate")],
    )
    .expect("admitted candidate");
    approve_claim(
        workspace,
        &observations,
        &anchors,
        &candidates,
        SignedAdmissionWire::sign(
            AdmissionKind::FactApproval,
            workspace.institution.clone(),
            workspace.id.clone(),
            workspace.owner.clone(),
            FactApprovalRequest {
                claim: claim.id.clone(),
                candidate_digest: candidate_claim_digest(&claim).expect("candidate digest"),
                subject,
                proposition: claim.proposition.clone(),
                acknowledged_status: ClaimStatus::Candidate,
                acknowledged_missed_axes: BTreeSet::new(),
                approved_at: at(),
            },
            &key,
        )
        .expect("signed owner approval"),
    )
    .expect("approved fact")
}

fn learning_delegation(
    owner: &PrincipalId,
    workspace: &InstitutionWorkspace,
    action: &str,
    sources: impl IntoIterator<Item = EvidenceId>,
) -> Delegation {
    let mut resources = BTreeSet::from([context_workspace_resource(&workspace.id)]);
    resources.extend(
        sources
            .into_iter()
            .map(|source| context_source_resource(&workspace.id, &source)),
    );
    Delegation {
        id: DelegationId::new(),
        issuer: owner.clone(),
        subject: owner.clone(),
        parent: None,
        actions: BTreeSet::from([action.to_string()]),
        resources,
        effects: BTreeSet::from([CONTEXT_READ_EFFECT]),
        data_classes: BTreeSet::from([DataClass::Public]),
        audience: BTreeSet::from(["operator".to_string()]),
        expires_at: "2026-09-10T00:00:00Z".parse().expect("valid expiry"),
        budget: budget(),
    }
}

fn source(
    workspace: &InstitutionWorkspace,
    fact: politeia_core::knowledge::ApprovedFact,
    id: EvidenceId,
    currency: KnowledgeCurrency,
    relevance: u32,
    data: DataClass,
) -> ContextSource {
    ContextSource {
        id,
        fact,
        observations: BTreeSet::from([ObservationId::new()]),
        evidence: BTreeSet::from([EvidenceId::new()]),
        adapter: AdapterId::new(),
        currency,
        data_classes: BTreeSet::from([data]),
        audiences: BTreeSet::from(["operator".to_string()]),
        sinks: BTreeSet::from(["local".to_string()]),
        trust_domain: workspace.trust_domain.clone(),
        relevance,
    }
}

#[test]
fn authorization_precedes_ranking_and_archive_cannot_displace_canonical_truth() {
    let workspace = workspace();
    let canonical_id = EvidenceId::new();
    let archive_id = EvidenceId::new();
    let forbidden_id = EvidenceId::new();
    let snapshot = LearningSnapshot {
        institution: workspace.institution.clone(),
        workspace: workspace.id.clone(),
        generation: RuntimeGenerationId::derive(b"active"),
        trust_domain: workspace.trust_domain.clone(),
        compiler_version: "learning-v1".to_string(),
        sources: vec![
            source(
                &workspace,
                approved_fact(&workspace, "canonical"),
                canonical_id.clone(),
                KnowledgeCurrency::Canonical,
                1,
                DataClass::Public,
            ),
            source(
                &workspace,
                approved_fact(&workspace, "archive"),
                archive_id.clone(),
                KnowledgeCurrency::Archive,
                999,
                DataClass::Public,
            ),
            source(
                &workspace,
                approved_fact(&workspace, "forbidden"),
                forbidden_id.clone(),
                KnowledgeCurrency::Canonical,
                10_000,
                DataClass::Secret,
            ),
        ],
        capabilities: ActiveCapabilities::default(),
    };
    let request = ContextRequest {
        institution: workspace.institution.clone(),
        workspace: workspace.id.clone(),
        generation: snapshot.generation.clone(),
        compiler_version: "learning-v1".to_string(),
        audience: "operator".to_string(),
        sink: "local".to_string(),
        trust_domain: workspace.trust_domain.clone(),
        limit: 3,
    };
    let compiled = compile_context(
        &snapshot,
        &workspace.owner,
        &learning_delegation(
            &workspace.owner,
            &workspace,
            COMPILE_CONTEXT_ACTION,
            [canonical_id.clone(), archive_id.clone()],
        ),
        &request,
        at(),
    )
    .expect("authorized public sources compile");
    assert_eq!(compiled.input_ids, vec![canonical_id, archive_id]);
    assert!(!compiled.input_ids.contains(&forbidden_id));
}

#[test]
fn ungranted_or_foreign_context_sources_never_reach_ranking() {
    let workspace = workspace();
    let source_id = EvidenceId::new();
    let snapshot = LearningSnapshot {
        institution: workspace.institution.clone(),
        workspace: workspace.id.clone(),
        generation: RuntimeGenerationId::derive(b"active"),
        trust_domain: workspace.trust_domain.clone(),
        compiler_version: "learning-v1".to_string(),
        sources: vec![source(
            &workspace,
            approved_fact(&workspace, "scoped"),
            source_id.clone(),
            KnowledgeCurrency::Canonical,
            1,
            DataClass::Public,
        )],
        capabilities: ActiveCapabilities::default(),
    };
    let request = ContextRequest {
        institution: workspace.institution.clone(),
        workspace: workspace.id.clone(),
        generation: snapshot.generation.clone(),
        compiler_version: snapshot.compiler_version.clone(),
        audience: "operator".to_string(),
        sink: "local".to_string(),
        trust_domain: workspace.trust_domain.clone(),
        limit: 1,
    };
    let empty_resource = Delegation {
        resources: BTreeSet::new(),
        ..learning_delegation(&workspace.owner, &workspace, COMPILE_CONTEXT_ACTION, [])
    };
    assert!(matches!(
        compile_context(&snapshot, &workspace.owner, &empty_resource, &request, at()),
        Err(ContextRefusal::WorkspaceResourceNotDelegated)
    ));
    let wrong_source = learning_delegation(
        &workspace.owner,
        &workspace,
        COMPILE_CONTEXT_ACTION,
        [EvidenceId::new()],
    );
    assert!(
        compile_context(&snapshot, &workspace.owner, &wrong_source, &request, at())
            .expect("workspace grant remains valid")
            .items
            .is_empty()
    );

    let mut foreign = workspace.clone();
    foreign.id = InstitutionWorkspaceId::new();
    let foreign_snapshot = LearningSnapshot {
        sources: vec![source(
            &workspace,
            approved_fact(&foreign, "foreign"),
            source_id,
            KnowledgeCurrency::Canonical,
            1,
            DataClass::Public,
        )],
        ..snapshot
    };
    assert!(matches!(
        compile_context(
            &foreign_snapshot,
            &workspace.owner,
            &learning_delegation(
                &workspace.owner,
                &workspace,
                COMPILE_CONTEXT_ACTION,
                foreign_snapshot
                    .sources
                    .iter()
                    .map(|source| source.id.clone()),
            ),
            &request,
            at(),
        ),
        Err(ContextRefusal::ForeignFactWorkspace)
    ));
}

#[test]
fn feedback_cannot_self_promote_or_mutate_context() {
    let workspace = workspace();
    let source_id = EvidenceId::new();
    let context_source = source(
        &workspace,
        approved_fact(&workspace, "canonical"),
        source_id.clone(),
        KnowledgeCurrency::Canonical,
        1,
        DataClass::Public,
    );
    let snapshot = LearningSnapshot {
        institution: workspace.institution.clone(),
        workspace: workspace.id.clone(),
        generation: RuntimeGenerationId::derive(b"active"),
        trust_domain: workspace.trust_domain.clone(),
        compiler_version: "learning-v1".to_string(),
        sources: vec![context_source.clone()],
        capabilities: ActiveCapabilities::default(),
    };
    let feedback = FeedbackRequest {
        institution: workspace.institution.clone(),
        workspace: workspace.id.clone(),
        generation: snapshot.generation.clone(),
        source: source_id,
        observation: context_source
            .observations
            .first()
            .expect("one observation")
            .clone(),
        evidence: context_source
            .evidence
            .first()
            .expect("one evidence")
            .clone(),
        feedback_digest: Digest::blake3(b"incorrect"),
    };
    let feedback_delegation = learning_delegation(
        &workspace.owner,
        &workspace,
        RECORD_FEEDBACK_ACTION,
        [context_source.id.clone()],
    );
    let proposal = record_feedback(
        &snapshot,
        &workspace.owner,
        &feedback_delegation,
        &feedback,
        at(),
    )
    .expect("exact provenance creates only proposal");
    assert_eq!(proposal.feedback_digest, feedback.feedback_digest);
    assert_eq!(snapshot.sources.len(), 1, "feedback has no mutation path");
    let capability_request = CapabilityRequest {
        institution: workspace.institution.clone(),
        workspace: workspace.id.clone(),
        generation: snapshot.generation.clone(),
    };
    assert!(
        discover_capabilities(
            &snapshot,
            &workspace.owner,
            &learning_delegation(
                &workspace.owner,
                &workspace,
                DISCOVER_CAPABILITIES_ACTION,
                [],
            ),
            &capability_request,
            at(),
        )
        .expect("active generation matches")
        .operations
        .is_empty()
    );
    assert!(matches!(
        discover_capabilities(
            &snapshot,
            &workspace.owner,
            &learning_delegation(&workspace.owner, &workspace, COMPILE_CONTEXT_ACTION, [],),
            &capability_request,
            at(),
        ),
        Err(ContextRefusal::ActionNotDelegated)
    ));
    assert!(matches!(
        record_feedback(
            &snapshot,
            &workspace.owner,
            &learning_delegation(
                &workspace.owner,
                &workspace,
                COMPILE_CONTEXT_ACTION,
                [context_source.id.clone()],
            ),
            &feedback,
            at(),
        ),
        Err(FeedbackRefusal::Authority(
            ContextRefusal::ActionNotDelegated
        ))
    ));
}

fn assessment_record(id: EvidenceId, subject: Digest) -> EvidenceRecord {
    EvidenceRecord {
        id,
        subject,
        producer: PrincipalId::new(),
        producer_delegation: DelegationId::new(),
        method: "fixture".to_string(),
        payload_digest: Digest::blake3(b"payload"),
        observed_at: at(),
        independence: IndependenceClass::HumanAuthority,
    }
}

fn correcting_delegation(authority: &PrincipalId) -> Delegation {
    Delegation {
        id: DelegationId::new(),
        issuer: authority.clone(),
        subject: authority.clone(),
        parent: None,
        actions: BTreeSet::from(["evidence.correct".to_string()]),
        resources: BTreeSet::new(),
        effects: BTreeSet::new(),
        data_classes: BTreeSet::new(),
        audience: BTreeSet::new(),
        expires_at: "2026-09-10T00:00:00Z".parse().expect("valid expiry"),
        budget: budget(),
    }
}

#[test]
fn correction_view_preserves_original_digest_and_surfaces_ambiguity() {
    let subject = Digest::blake3(b"billing");
    let prior = assessment_record(EvidenceId::new(), subject.clone());
    let first_correction = assessment_record(EvidenceId::new(), subject.clone());
    let second_correction = assessment_record(EvidenceId::new(), subject.clone());
    let original_digest = prior.digest().expect("digest original evidence");
    let registry = TrustedEvidenceRegistry::from_trusted_bootstrap([
        prior.clone(),
        first_correction.clone(),
        second_correction.clone(),
    ])
    .expect("unique evidence");
    let authority = PrincipalId::new();
    let delegation = correcting_delegation(&authority);
    let relations = [
        AssessmentRelation {
            id: EvidenceId::new(),
            kind: RelationKind::Correction,
            prior: prior.id.clone(),
            successor: first_correction.id.clone(),
            authority: authority.clone(),
            authority_delegation: delegation.id.clone(),
            asserted_at: at(),
        },
        AssessmentRelation {
            id: EvidenceId::new(),
            kind: RelationKind::Correction,
            prior: prior.id.clone(),
            successor: second_correction.id.clone(),
            authority,
            authority_delegation: delegation.id.clone(),
            asserted_at: at(),
        },
    ];
    let delegated = BTreeMap::from([(delegation.id.clone(), delegation)]);
    let corrected = correction_view(&subject, &registry, &relations[..1], &delegated)
        .expect("one authorized correction changes the derived view");
    assert!(matches!(
        corrected,
        Projection::Current {
            ref record,
            ref corrections
        } if record == &prior.id && corrections == &vec![first_correction.id.clone()]
    ));
    let view = correction_view(&subject, &registry, &relations, &delegated)
        .expect("relations are authorized even though they are ambiguous");
    assert!(matches!(
        view,
        Projection::Unresolved(Unresolved::ConflictingCorrections { .. })
    ));
    assert_eq!(
        prior.digest().expect("digest original evidence"),
        original_digest
    );
}
