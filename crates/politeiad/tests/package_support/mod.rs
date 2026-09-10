//! Synthetic, process-bound inputs for the commissioning-package acceptance test.
//!
//! This module deliberately returns inert host configuration, files, and
//! signing identities. It never creates a service, coordinator, dispatcher, or
//! storage handle, so the acceptance test must cross the installed daemon's
//! Unix socket for every semantic transition.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use ed25519_dalek::SigningKey;
use jiff::{SignedDuration, Timestamp};
use politeia_core::{
    AdapterId, CommissioningRecordId, DataClass, Delegation, DelegationId, Digest, Effect,
    EvidenceId, InstitutionId, InstitutionWorkspaceId, ObservationId, PolicyBundleId, PrincipalId,
    ResourceBudget, RuntimeGenerationId, SourceCaptureId,
    evidence::{EvidenceRequest, IndependenceClass},
    generation::{
        ApprovedGenerationInputs, CommissioningCapability, ReproducibilityContract,
        RuntimeGenerationInputs,
    },
    institution::{InstitutionWorkspace, TrustDomainId},
    knowledge::{
        CandidateClaimRequest, ClaimStatus, FactApprovalRequest, ObservationRequest,
        SourceCaptureRequest, candidate_claim_digest, observation_evidence_payload_digest,
    },
    lifecycle::{DeploymentTopology, LifecycleProfile},
    reconnaissance::{RECONNOITRE_ACTION, ReconnaissanceScope},
    trust::{AdmissionKind, SignedAdmissionWire, WorkspaceBootstrapRequest},
};
use politeia_evidence::assurance::{ActivationProof, ControlRun};
use politeiad::config::{HostTrustConfiguration, InstalledTrustAnchor};
use politeiad::{
    learning::{
        COMPILE_CONTEXT_ACTION, CONTEXT_READ_EFFECT, ContextRequest, KnowledgeCurrency,
        context_source_resource, context_workspace_resource,
    },
    service_learning::{LearningDisclosureIngress, LearningRequest, LearningSourceRequest},
};

mod commissioning;
mod handoff;
mod handoff_receipt;
pub(crate) mod learning;
mod lifecycle;
pub(crate) mod operational;
use politeiad::service_generation::{
    ActivationAssurance, CommissioningReceipt, GenerationTransitionAction,
    GenerationTransitionRequest, activation_assurance_digest,
};

/// The two intentionally disjoint reference institutions exercised by the package.
#[derive(Clone, Copy, Debug)]
pub(crate) enum ReferenceInstitutionKind {
    /// A synthetic software-development institution.
    SoftwareDevelopment,
    /// A synthetic analytics institution.
    Analytics,
}

impl ReferenceInstitutionKind {
    /// Stable public fixture directory name.
    pub(crate) const fn directory(self) -> &'static str {
        match self {
            Self::SoftwareDevelopment => "software-development",
            Self::Analytics => "analytics",
        }
    }

    /// A compact filesystem label that keeps the Unix socket beneath its length limit.
    const fn short_label(self) -> &'static str {
        match self {
            Self::SoftwareDevelopment => "software",
            Self::Analytics => "analytics",
        }
    }

    /// A distinct trust-domain label for the synthetic institution.
    fn trust_domain(self) -> &'static str {
        match self {
            Self::SoftwareDevelopment => "reference.software-development.local",
            Self::Analytics => "reference.analytics.local",
        }
    }
}

/// Separate identities installed for ownership, commissioning, work, and assurance.
pub(crate) struct SigningIdentities {
    /// Institutional owner who may approve exact constitutional subjects.
    pub(crate) owner: PrincipalId,
    /// Temporary commissioning identity.
    pub(crate) commissioner: PrincipalId,
    /// Operational canary identity.
    pub(crate) worker: PrincipalId,
    /// Persistent control producer, independent of the worker and commissioner.
    pub(crate) control_producer: PrincipalId,
    /// Independent verification identity.
    pub(crate) verifier: PrincipalId,
    /// Fresh handoff identity, deliberately distinct from the commissioner.
    pub(crate) replacement: PrincipalId,
    owner_key: SigningKey,
    commissioner_key: SigningKey,
    worker_key: SigningKey,
    control_producer_key: SigningKey,
    verifier_key: SigningKey,
    replacement_key: SigningKey,
}

impl SigningIdentities {
    /// Return the owner signing key only to construct a raw signed document.
    pub(crate) fn owner_key(&self) -> &SigningKey {
        &self.owner_key
    }

    /// Return the commissioner signing key only to construct a raw signed document.
    pub(crate) fn commissioner_key(&self) -> &SigningKey {
        &self.commissioner_key
    }

    /// Return the worker signing key only to construct a raw signed document.
    pub(crate) fn worker_key(&self) -> &SigningKey {
        &self.worker_key
    }

    /// Return the persistent assessor key to sign actual control observations.
    pub(crate) fn control_producer_key(&self) -> &SigningKey {
        &self.control_producer_key
    }

    /// Return the verifier signing key only to construct a raw signed document.
    pub(crate) fn verifier_key(&self) -> &SigningKey {
        &self.verifier_key
    }

    /// Return the replacement signing key only to construct a raw signed document.
    pub(crate) fn replacement_key(&self) -> &SigningKey {
        &self.replacement_key
    }
}

/// One installed fixture with real public source member files copied into a private test root.
pub(crate) struct ReferenceFixture {
    /// Which public reference corpus supplies the source facts.
    pub(crate) kind: ReferenceInstitutionKind,
    /// Institution-owned temporary root used as a process prefix and source root.
    pub(crate) root: PathBuf,
    /// Actual checked-in synthetic source document copied into the source root.
    pub(crate) source_document: PathBuf,
    /// Complete actual public artifact input directory, outside the installation.
    generation_material: PathBuf,
    /// Installed read-only adapter identity used by capture documents.
    adapter: AdapterId,
    /// Inert host configuration passed to `politeiad initialize`.
    pub(crate) host_trust: HostTrustConfiguration,
    /// Separate signing material retained by the test process, never written to the host config.
    pub(crate) identities: SigningIdentities,
}

/// Raw signed capture material, still inert until daemon admission.
pub(crate) struct CaptureDocuments {
    /// JSON supplied to the daemon snapshot operation.
    pub(crate) document: serde_json::Value,
    /// Authenticated capture shape used to derive the bootstrap's exact grant resources.
    capture: SourceCaptureRequest,
    /// Evidence identity persisted with the source capture.
    pub(crate) evidence: EvidenceId,
    /// Observation identity a later candidate may cite.
    observation: ObservationRequest,
}

/// Raw candidate and owner approval documents, still inert until daemon admission.
pub(crate) struct CandidateDocuments {
    /// Interpreter-signed candidate wire.
    pub(crate) candidate: SignedAdmissionWire<CandidateClaimRequest>,
    /// Owner-signed exact candidate approval wire.
    pub(crate) approval: SignedAdmissionWire<FactApprovalRequest>,
}

/// Owner-signed approved content ready for the daemon's learning ingress.
pub(crate) struct LearningSourceDocuments {
    /// JSON supplied through the commissioning socket after candidate approval.
    pub(crate) document: serde_json::Value,
    /// Durable source identity for later context, feedback, and correction input.
    pub(crate) source: EvidenceId,
}

/// Complete staged artifact paths and a signed publish request.
pub(crate) struct GenerationDocuments {
    /// Inputs signed by the selected commissioner. The service must still
    /// re-admit this wire and reconstruct the supplied receipt.
    pub(crate) inputs: SignedAdmissionWire<RuntimeGenerationInputs>,
    /// Transport JSON for `commissioning { kind: generation, ... }`.
    pub(crate) publish: serde_json::Value,
}

/// Real assurance wires required for an activation or rollback call.
///
/// These values are intentionally supplied from an independent test control
/// path. The fixture cannot synthesize a clean result, its direct grants, or
/// a proof and call that an activation test.
#[derive(Clone)]
pub(crate) struct ActivationDocuments {
    /// Independent verifier calibration recorded before the producer run.
    pub(crate) calibration: SignedAdmissionWire<EvidenceRequest>,
    /// Signed run of the exact lifecycle control.
    pub(crate) run: SignedAdmissionWire<ControlRun>,
    /// Durable direct authority for the control-run producer.
    pub(crate) run_authority: SignedAdmissionWire<Delegation>,
    /// Signed proof from an independent verifier.
    pub(crate) proof: SignedAdmissionWire<ActivationProof>,
    /// Durable direct authority for the verifier.
    pub(crate) proof_authority: SignedAdmissionWire<Delegation>,
}

impl ReferenceFixture {
    /// Create one synthetic institution fixture under a fresh temporary directory.
    ///
    /// The approved generation binds the exact source, schema, migration, and
    /// public metadata files materialized by the acceptance test. This helper
    /// only lays out the disjoint identity and installation boundary.
    #[expect(
        clippy::expect_used,
        reason = "the acceptance fixture must fail loudly when public test inputs are absent"
    )]
    pub(crate) fn new(kind: ReferenceInstitutionKind, executable: &Path) -> Self {
        let root = std::env::temp_dir().join(format!(
            "plp-{}-{}",
            kind.short_label(),
            uuid::Uuid::now_v7()
        ));
        fs::create_dir(&root).expect("fresh package fixture root creates");
        let source_root = root.join("selected-public-source");
        fs::create_dir(&source_root).expect("selected source root creates");
        let source_document = source_root.join("institution.md");
        fs::copy(
            repository_root()
                .join("examples/reference-institutions")
                .join(kind.directory())
                .join("README.md"),
            &source_document,
        )
        .expect("public synthetic fixture source copies");
        let adapter = AdapterId::new();
        let generation_material = root.join("generation-material");
        fs::create_dir(&generation_material).expect("generation material root creates");
        let approved_generation = stage_public_generation_material(
            &generation_material,
            &source_document,
            executable,
            &adapter,
        );

        let identities = SigningIdentities {
            owner: PrincipalId::new(),
            commissioner: PrincipalId::new(),
            worker: PrincipalId::new(),
            control_producer: PrincipalId::new(),
            verifier: PrincipalId::new(),
            replacement: PrincipalId::new(),
            owner_key: fixture_signing_key(kind, 0x11),
            commissioner_key: fixture_signing_key(kind, 0x22),
            worker_key: fixture_signing_key(kind, 0x33),
            control_producer_key: fixture_signing_key(kind, 0x66),
            verifier_key: fixture_signing_key(kind, 0x44),
            replacement_key: fixture_signing_key(kind, 0x55),
        };
        let institution = InstitutionId::new();
        let workspace_id = InstitutionWorkspaceId::new();
        let policy_bytes = fs::read(generation_material.join("policy/constitution.md"))
            .expect("staged policy is readable");
        let workspace = InstitutionWorkspace {
            id: workspace_id,
            institution,
            trust_domain: kind
                .trust_domain()
                .parse::<TrustDomainId>()
                .expect("fixture trust domain is canonical"),
            owner: identities.owner.clone(),
            owner_delegation: DelegationId::new(),
            approved_model_digest: Digest::blake3(b"synthetic broad institutional model"),
            policy_bundle: PolicyBundleId::new(),
            policy_digest: Digest::blake3(&policy_bytes),
            approved_generation,
            secret_references: BTreeSet::new(),
        };
        let anchors = vec![
            anchor(
                &identities.owner,
                identities.owner_key(),
                [
                    AdmissionKind::WorkspaceBootstrap,
                    AdmissionKind::FactApproval,
                    AdmissionKind::Delegation,
                    AdmissionKind::Generation,
                    AdmissionKind::GenerationTransition,
                    AdmissionKind::Revocation,
                    AdmissionKind::LearningSource,
                    AdmissionKind::Evidence,
                    AdmissionKind::LearningCorrection,
                ],
            ),
            anchor(
                &identities.commissioner,
                identities.commissioner_key(),
                [
                    AdmissionKind::SourceCapture,
                    AdmissionKind::Evidence,
                    AdmissionKind::Observation,
                    AdmissionKind::CandidateClaim,
                    AdmissionKind::Delegation,
                    AdmissionKind::Generation,
                    AdmissionKind::GenerationTransition,
                    AdmissionKind::LearningContext,
                    AdmissionKind::OperationIntent,
                ],
            ),
            anchor(
                &identities.worker,
                identities.worker_key(),
                [
                    AdmissionKind::Delegation,
                    AdmissionKind::OperationIntent,
                    AdmissionKind::LearningContext,
                    AdmissionKind::LearningDiscovery,
                    AdmissionKind::LearningFeedback,
                ],
            ),
            anchor(
                &identities.control_producer,
                identities.control_producer_key(),
                [
                    AdmissionKind::ControlRun,
                    AdmissionKind::ActivationProof,
                    AdmissionKind::Evidence,
                ],
            ),
            anchor(
                &identities.verifier,
                identities.verifier_key(),
                [
                    AdmissionKind::Verification,
                    AdmissionKind::Evidence,
                    AdmissionKind::ActivationProof,
                ],
            ),
            anchor(
                &identities.replacement,
                identities.replacement_key(),
                [AdmissionKind::Delegation, AdmissionKind::Generation],
            ),
        ];
        let bootstrap = SignedAdmissionWire::sign(
            AdmissionKind::WorkspaceBootstrap,
            workspace.institution.clone(),
            workspace.id.clone(),
            workspace.owner.clone(),
            WorkspaceBootstrapRequest {
                workspace: workspace.clone(),
            },
            identities.owner_key(),
        )
        .expect("owner signs matching workspace bootstrap");
        Self {
            kind,
            root,
            source_document,
            generation_material,
            adapter,
            host_trust: HostTrustConfiguration {
                workspace,
                anchors,
                bootstrap,
            },
            identities,
        }
    }

    /// Return this installation's private prefix.
    pub(crate) fn prefix(&self) -> PathBuf {
        self.root.join("installation")
    }

    /// Produce the owner-root grant that anchors every temporary package grant.
    pub(crate) fn owner_root_delegation(&self) -> Delegation {
        Delegation {
            id: self.host_trust.workspace.owner_delegation.clone(),
            issuer: self.identities.owner.clone(),
            subject: self.identities.owner.clone(),
            parent: None,
            actions: BTreeSet::from([politeia_core::commissioning::COMMISSION_ACTION.to_owned()]),
            resources: BTreeSet::from([
                politeia_core::commissioning::commissioning_workspace_resource(
                    &self.host_trust.workspace.id,
                ),
            ]),
            effects: BTreeSet::new(),
            data_classes: BTreeSet::new(),
            audience: BTreeSet::from([
                politeia_core::commissioning::commissioning_institution_audience(
                    &self.host_trust.workspace.institution,
                ),
            ]),
            expires_at: Timestamp::now() + SignedDuration::from_hours(2),
            budget: ResourceBudget {
                wall_ms: Some(120_000),
                cpu_ms: Some(20_000),
                memory_bytes: Some(128 * 1024 * 1024),
                io_bytes: Some(2 * 1024 * 1024),
                network_bytes: Some(2 * 1024 * 1024),
                external_cost_microunits: Some(0),
            },
        }
    }

    /// Produce temporary authority to derive and publish approved generations.
    pub(crate) fn commissioner_delegation(&self, owner_grant: &Delegation) -> Delegation {
        Delegation {
            id: DelegationId::new(),
            issuer: self.identities.owner.clone(),
            subject: self.identities.commissioner.clone(),
            parent: Some(owner_grant.id.clone()),
            actions: owner_grant.actions.clone(),
            resources: owner_grant.resources.clone(),
            effects: owner_grant.effects.clone(),
            data_classes: owner_grant.data_classes.clone(),
            audience: owner_grant.audience.clone(),
            expires_at: Timestamp::now() + SignedDuration::from_hours(1),
            budget: ResourceBudget {
                wall_ms: Some(60_000),
                cpu_ms: Some(10_000),
                memory_bytes: Some(64 * 1024 * 1024),
                io_bytes: Some(1024 * 1024),
                network_bytes: Some(1024 * 1024),
                external_cost_microunits: Some(0),
            },
        }
    }

    /// Construct the one direct, descriptor-bound pre-generation capture grant
    /// and its matching signed capture documents.
    ///
    /// This is intentionally separate from the nested general-purpose grant:
    /// the bootstrap dispatcher admits only a direct owner grant with the five
    /// capture-derived resources. The caller must durably admit it through the
    /// service's dedicated bootstrap path before sending `document` to
    /// `snapshot`.
    pub(crate) fn bootstrap_capture_documents(&self) -> (Delegation, CaptureDocuments) {
        let mut delegation = Delegation {
            id: DelegationId::new(),
            issuer: self.identities.owner.clone(),
            subject: self.identities.commissioner.clone(),
            parent: None,
            actions: BTreeSet::from([RECONNOITRE_ACTION.to_owned()]),
            resources: BTreeSet::new(),
            effects: BTreeSet::from([Effect::ReadExternalSystem]),
            data_classes: BTreeSet::from([DataClass::Internal]),
            audience: BTreeSet::from([format!(
                "institution:{}",
                self.host_trust.workspace.institution.0
            )]),
            expires_at: Timestamp::now() + SignedDuration::from_hours(1),
            budget: ResourceBudget {
                wall_ms: Some(60_000),
                cpu_ms: Some(10_000),
                memory_bytes: Some(64 * 1024 * 1024),
                io_bytes: Some(1024 * 1024),
                network_bytes: Some(1024 * 1024),
                external_cost_microunits: Some(0),
            },
        };
        let documents = self.source_capture_submission(&delegation);
        delegation.resources =
            politeia_policy::bootstrap::bootstrap_capture_resources(&documents.capture);
        (delegation, documents)
    }

    /// Produce a fresh owner-rooted grant for the named replacement maintainer.
    pub(crate) fn replacement_delegation(&self, owner_grant: &Delegation) -> Delegation {
        let mut replacement = self.commissioner_delegation(owner_grant);
        replacement.id = DelegationId::new();
        replacement.subject = self.identities.replacement.clone();
        replacement
    }

    /// Sign the temporary delegation as raw input to the commissioning socket operation.
    pub(crate) fn signed_commissioner_delegation(
        &self,
        delegation: Delegation,
    ) -> SignedAdmissionWire<Delegation> {
        SignedAdmissionWire::sign(
            AdmissionKind::Delegation,
            self.host_trust.workspace.institution.clone(),
            self.host_trust.workspace.id.clone(),
            self.identities.owner.clone(),
            delegation,
            self.identities.owner_key(),
        )
        .expect("owner signs temporary commissioner delegation")
    }

    /// Produce one complete, raw signed source-capture submission.
    ///
    /// The caller copies `source_document` into the installed workspace before
    /// it sends this document. The daemon independently reads that installed
    /// file through its descriptor-bound adapter and compares this manifest.
    pub(crate) fn source_capture_submission(&self, delegation: &Delegation) -> CaptureDocuments {
        let member = "institution.md".to_owned();
        let bytes =
            fs::read(&self.source_document).expect("public source document remains readable");
        let members = vec![politeiad::source::SourceMember {
            path: member.clone(),
            content_digest: Digest::blake3(&bytes),
            byte_len: u64::try_from(bytes.len()).expect("fixture source length fits in u64"),
        }];
        let content_manifest_digest = Digest::blake3(
            &serde_json::to_vec(&members).expect("source member manifest serializes"),
        );
        let observed_at = Timestamp::now();
        let scope = ReconnaissanceScope {
            commissioner: self.identities.commissioner.clone(),
            delegation: delegation.id.clone(),
            sources: BTreeSet::from([format!("reference:{}:source", self.kind.directory())]),
            adapters: BTreeSet::from([self.adapter.clone()]),
            expires_at: delegation.expires_at,
        };
        let capture_request = SourceCaptureRequest {
            id: SourceCaptureId::new(),
            source: format!("reference:{}:source", self.kind.directory()),
            adapter: self.adapter.clone(),
            subject: Digest::blake3(self.kind.directory().as_bytes()),
            statement: Digest::blake3(&bytes),
            observed_at,
            reconnaissance_delegation: delegation.id.clone(),
            reconnaissance: scope.clone(),
            manifest: BTreeSet::from([member]),
            descriptor_digest: Digest::blake3(
                &serde_json::to_vec(&scope).expect("reconnaissance descriptor serializes"),
            ),
            content_manifest_digest,
        };
        let evidence_id = EvidenceId::new();
        let observation_request = ObservationRequest {
            id: ObservationId::new(),
            capture: capture_request.id.clone(),
            capture_manifest_digest: capture_request.content_manifest_digest.clone(),
            source: capture_request.source.clone(),
            adapter: capture_request.adapter.clone(),
            subject: capture_request.subject.clone(),
            statement: capture_request.statement.clone(),
            observed_at,
            evidence: evidence_id.clone(),
        };
        let evidence_request = EvidenceRequest {
            id: evidence_id,
            subject: observation_request.subject.clone(),
            producer_delegation: delegation.id.clone(),
            method: "synthetic descriptor-bound public source capture".to_owned(),
            payload_digest: observation_evidence_payload_digest(
                &self.host_trust.workspace.id,
                &observation_request,
            )
            .expect("observation evidence payload binds canonically"),
            observed_at,
            independence: IndependenceClass::SelfReported,
        };
        let capture = SignedAdmissionWire::sign(
            AdmissionKind::SourceCapture,
            self.host_trust.workspace.institution.clone(),
            self.host_trust.workspace.id.clone(),
            self.identities.commissioner.clone(),
            capture_request,
            self.identities.commissioner_key(),
        )
        .expect("commissioner signs source capture");
        let evidence = SignedAdmissionWire::sign(
            AdmissionKind::Evidence,
            self.host_trust.workspace.institution.clone(),
            self.host_trust.workspace.id.clone(),
            self.identities.commissioner.clone(),
            evidence_request,
            self.identities.commissioner_key(),
        )
        .expect("commissioner signs capture evidence");
        let observation = SignedAdmissionWire::sign(
            AdmissionKind::Observation,
            self.host_trust.workspace.institution.clone(),
            self.host_trust.workspace.id.clone(),
            self.identities.commissioner.clone(),
            observation_request,
            self.identities.commissioner_key(),
        )
        .expect("commissioner signs source observation");
        CaptureDocuments {
            document: serde_json::json!({
                "capture": capture,
                "evidence": evidence,
                "observation": observation,
                "reconnaissance": scope,
            }),
            capture: capture.payload.clone(),
            evidence: evidence.payload.id.clone(),
            observation: observation.payload,
        }
    }

    /// Build a candidate and exact owner approval over one future admitted observation.
    pub(crate) fn candidate_documents(
        &self,
        delegation: &Delegation,
        capture: &CaptureDocuments,
    ) -> CandidateDocuments {
        let candidate = CandidateClaimRequest {
            id: politeia_core::ClaimId::new(),
            workspace: self.host_trust.workspace.id.clone(),
            subject: capture.observation.subject.clone(),
            proposition: Digest::blake3(
                &fs::read(&self.source_document)
                    .expect("approved public source content remains readable"),
            ),
            supported_by: BTreeMap::from([(
                capture.observation.source.clone(),
                BTreeSet::from([capture.observation.id.clone()]),
            )]),
            contradicted_by: BTreeMap::new(),
            missed_axes: BTreeSet::from(["future institution change".to_owned()]),
            interpreter: self.identities.commissioner.clone(),
            interpreter_delegation: delegation.id.clone(),
        };
        let candidate_wire = SignedAdmissionWire::sign(
            AdmissionKind::CandidateClaim,
            self.host_trust.workspace.institution.clone(),
            self.host_trust.workspace.id.clone(),
            self.identities.commissioner.clone(),
            candidate.clone(),
            self.identities.commissioner_key(),
        )
        .expect("commissioner signs candidate claim");
        let approval = FactApprovalRequest {
            claim: candidate.id.clone(),
            candidate_digest: candidate_claim_digest(&candidate)
                .expect("candidate claim canonically digests"),
            subject: candidate.subject.clone(),
            proposition: candidate.proposition.clone(),
            acknowledged_status: ClaimStatus::Candidate,
            acknowledged_missed_axes: candidate.missed_axes.clone(),
            approved_at: Timestamp::now(),
        };
        CandidateDocuments {
            candidate: candidate_wire,
            approval: SignedAdmissionWire::sign(
                AdmissionKind::FactApproval,
                self.host_trust.workspace.institution.clone(),
                self.host_trust.workspace.id.clone(),
                self.identities.owner.clone(),
                approval,
                self.identities.owner_key(),
            )
            .expect("owner signs exact candidate approval"),
        }
    }

    /// Construct an envelope that falsely names the owner while using the
    /// commissioner's private key. It is raw adversarial transport input and
    /// must fail installed-owner signature admission before fact approval.
    pub(crate) fn forged_candidate_approval(
        &self,
        candidate: &CandidateDocuments,
    ) -> serde_json::Value {
        let forged = SignedAdmissionWire::sign(
            AdmissionKind::FactApproval,
            self.host_trust.workspace.institution.clone(),
            self.host_trust.workspace.id.clone(),
            self.identities.owner.clone(),
            candidate.approval.payload.clone(),
            self.identities.commissioner_key(),
        )
        .expect("commissioner can construct an intentionally invalid owner envelope");
        serde_json::json!({
            "kind": "approve_claim",
            "candidate": candidate.candidate.clone(),
            "approval": forged,
        })
    }

    /// Build a bounded commissioner request for the owner-pinned source using
    /// the immutable bootstrap runtime identity.
    pub(crate) fn bootstrap_context_documents(
        &self,
        source: &EvidenceId,
    ) -> (Delegation, serde_json::Value) {
        let delegation = Delegation {
            id: DelegationId::new(),
            issuer: self.identities.owner.clone(),
            subject: self.identities.commissioner.clone(),
            parent: None,
            actions: BTreeSet::from([COMPILE_CONTEXT_ACTION.to_owned()]),
            resources: BTreeSet::from([
                context_workspace_resource(&self.host_trust.workspace.id),
                context_source_resource(&self.host_trust.workspace.id, source),
            ]),
            effects: BTreeSet::from([CONTEXT_READ_EFFECT]),
            data_classes: BTreeSet::from([DataClass::Internal]),
            audience: BTreeSet::from(["commissioning".to_owned()]),
            expires_at: Timestamp::now() + SignedDuration::from_hours(1),
            budget: ResourceBudget {
                wall_ms: Some(30_000),
                cpu_ms: Some(10_000),
                memory_bytes: Some(32 * 1024 * 1024),
                io_bytes: Some(1024 * 1024),
                network_bytes: Some(0),
                external_cost_microunits: Some(0),
            },
        };
        let generation = RuntimeGenerationId::from_digest(
            politeiad::service_learning::durable_signed_wire_digest(&self.host_trust.bootstrap)
                .expect("bootstrap wire canonically digests"),
        );
        let request = LearningDisclosureIngress {
            id: CommissioningRecordId::new(),
            requester: self.identities.commissioner.clone(),
            delegation: delegation.id.clone(),
            budget: delegation.budget.clone(),
            input: ContextRequest {
                institution: self.host_trust.workspace.institution.clone(),
                workspace: self.host_trust.workspace.id.clone(),
                generation,
                compiler_version: "learning-v1".to_owned(),
                audience: "commissioning".to_owned(),
                sink: "package-acceptance".to_owned(),
                trust_domain: self.host_trust.workspace.trust_domain.clone(),
                limit: 1,
            },
        };
        let signed = SignedAdmissionWire::sign(
            AdmissionKind::LearningContext,
            self.host_trust.workspace.institution.clone(),
            self.host_trust.workspace.id.clone(),
            self.identities.commissioner.clone(),
            request,
            self.identities.commissioner_key(),
        )
        .expect("commissioner signs context request");
        (
            delegation,
            serde_json::json!({"kind":"learning", "request": LearningRequest::CompileContext { request: signed, active_submission: None }}),
        )
    }

    pub(crate) fn forged_context_requester(&self, delegation: &Delegation) -> serde_json::Value {
        let generation = RuntimeGenerationId::from_digest(
            politeiad::service_learning::durable_signed_wire_digest(&self.host_trust.bootstrap)
                .expect("bootstrap wire canonically digests"),
        );
        let request = LearningDisclosureIngress {
            id: CommissioningRecordId::new(),
            requester: self.identities.worker.clone(),
            delegation: delegation.id.clone(),
            budget: delegation.budget.clone(),
            input: ContextRequest {
                institution: self.host_trust.workspace.institution.clone(),
                workspace: self.host_trust.workspace.id.clone(),
                generation,
                compiler_version: "learning-v1".to_owned(),
                audience: "commissioning".to_owned(),
                sink: "package-acceptance".to_owned(),
                trust_domain: self.host_trust.workspace.trust_domain.clone(),
                limit: 1,
            },
        };
        let signed = SignedAdmissionWire::sign(
            AdmissionKind::LearningContext,
            self.host_trust.workspace.institution.clone(),
            self.host_trust.workspace.id.clone(),
            self.identities.commissioner.clone(),
            request,
            self.identities.commissioner_key(),
        )
        .expect("commissioner signs forged requester envelope");
        serde_json::json!({"kind":"learning", "request": LearningRequest::CompileContext { request: signed, active_submission: None }})
    }

    /// Bind the exact owner-approved fact to public content for later learning.
    ///
    /// This may be sent only after the candidate and its owner approval have
    /// been durably admitted by the daemon. The service repeats each lookup,
    /// signature check, and content/proposition equality check before commit.
    pub(crate) fn learning_source_documents(
        &self,
        capture: &CaptureDocuments,
        candidate: &CandidateDocuments,
    ) -> LearningSourceDocuments {
        // A learning source is an approved view of already-admitted capture
        // evidence. Its stable identity is therefore the admitted evidence
        // identity, which is also required in its durable evidence provenance.
        let source = capture.evidence.clone();
        let content = fs::read(&self.source_document)
            .expect("owner-approved public content remains readable");
        let approval_digest =
            politeiad::service_learning::durable_signed_wire_digest(&candidate.approval)
                .expect("approval wire canonically encodes for durable storage");
        let request = LearningSourceRequest {
            id: source.clone(),
            claim: candidate.candidate.payload.id.clone(),
            approval_digest,
            subject: candidate.candidate.payload.subject.clone(),
            proposition: candidate.candidate.payload.proposition.clone(),
            content,
            evidence: BTreeSet::from([source.clone()]),
            observations: BTreeSet::from([capture.observation.id.clone()]),
            captures: BTreeSet::from([capture.capture.id.clone()]),
            adapter: self.adapter.clone(),
            currency: KnowledgeCurrency::Canonical,
            data_classes: BTreeSet::from([DataClass::Internal]),
            audiences: BTreeSet::from(["commissioning".to_owned()]),
            sinks: BTreeSet::from(["package-acceptance".to_owned()]),
            trust_domain: self.host_trust.workspace.trust_domain.clone(),
            relevance: 100,
        };
        let signed = SignedAdmissionWire::sign(
            AdmissionKind::LearningSource,
            self.host_trust.workspace.institution.clone(),
            self.host_trust.workspace.id.clone(),
            self.identities.owner.clone(),
            request,
            self.identities.owner_key(),
        )
        .expect("owner signs approved learning source");
        LearningSourceDocuments {
            document: serde_json::json!({
                "kind": "learning",
                "request": LearningRequest::RegisterSource { source: signed },
            }),
            source,
        }
    }

    /// Build the exact signed publication request for the already-staged
    /// approved public bytes under the installed workspace.
    ///
    /// `receipt` is deliberately supplied by the caller because only the
    /// daemon's admitted evidence and reconstructed commissioning record can
    /// make it authoritative. This helper creates transport input; it never
    /// treats the receipt as admitted state.
    pub(crate) fn generation_documents(
        &self,
        commissioner: &Delegation,
        receipt: &CommissioningReceipt,
    ) -> GenerationDocuments {
        let workspace = &self.host_trust.workspace;
        let inputs = RuntimeGenerationInputs {
            institution: workspace.institution.clone(),
            workspace: workspace.id.clone(),
            workspace_digest: workspace
                .digest()
                .expect("installed workspace canonically digests"),
            trust_domain: workspace.trust_domain.clone(),
            policy_bundle: workspace.policy_bundle.clone(),
            policy_digest: workspace.policy_digest.clone(),
            commissioning_record: receipt.record.clone(),
            commissioning_record_digest: receipt.record_digest.clone(),
            approved: workspace.approved_generation.clone(),
        };
        let inputs = SignedAdmissionWire::sign(
            AdmissionKind::Generation,
            workspace.institution.clone(),
            workspace.id.clone(),
            self.identities.commissioner.clone(),
            inputs,
            self.identities.commissioner_key(),
        )
        .expect("selected commissioner signs generation inputs");
        assert_eq!(commissioner.subject, self.identities.commissioner);
        let sources = artifact_source_paths(&self.adapter);
        let publish = serde_json::json!({
            "kind": "generation",
            "request": {
                "kind": "publish",
                "inputs": inputs,
                "commissioning": {
                    "receipt": receipt,
                    "publication_delegation": commissioner.id,
                },
                "sources": sources,
            },
        });
        GenerationDocuments { inputs, publish }
    }

    /// Stage the complete approved artifact byte set under the installed
    /// workspace without creating a lifecycle request.
    pub(crate) fn stage_generation_artifacts(&self) {
        let target = self.prefix().join("workspace/generation");
        copy_tree(&self.generation_material, &target);
    }

    /// Serialize an activation or rollback request around independently
    /// produced assurance and a matching installed-owner deployment decision.
    pub(crate) fn activation_request(
        &self,
        kind: &str,
        generation: Digest,
        expected_revision: i64,
        expected_active: Option<Digest>,
        assurance: &ActivationDocuments,
    ) -> serde_json::Value {
        let action = transition_action(kind);
        let transition = self.generation_transition_authorization(
            action,
            generation,
            expected_revision,
            expected_active,
            assurance,
        );
        Self::activation_request_with_transition(assurance, &transition)
    }

    /// Sign the installed owner's exact active-generation decision for a
    /// complete lifecycle assurance document.
    pub(crate) fn generation_transition_authorization(
        &self,
        action: GenerationTransitionAction,
        generation: Digest,
        expected_revision: i64,
        expected_active: Option<Digest>,
        assurance: &ActivationDocuments,
    ) -> SignedAdmissionWire<GenerationTransitionRequest> {
        let assurance = ActivationAssurance {
            calibration: assurance.calibration.clone(),
            run: assurance.run.clone(),
            run_authority: assurance.run_authority.clone(),
            proof: assurance.proof.clone(),
            proof_authority: assurance.proof_authority.clone(),
        };
        let transition = GenerationTransitionRequest {
            evidence: EvidenceId::new(),
            action,
            generation,
            expected_revision,
            expected_active,
            assurance_digest: activation_assurance_digest(&assurance)
                .expect("activation assurance canonically encodes"),
        };
        SignedAdmissionWire::sign(
            AdmissionKind::GenerationTransition,
            self.host_trust.workspace.institution.clone(),
            self.host_trust.workspace.id.clone(),
            self.identities.owner.clone(),
            transition,
            self.identities.owner_key(),
        )
        .expect("installed owner signs generation transition")
    }

    /// Serialize a lifecycle request with a caller-supplied signed transition.
    ///
    /// The process fixture uses this only to establish that a valid owner
    /// signature over different action, target, or assurance bytes still
    /// refuses at the service boundary.
    pub(crate) fn activation_request_with_transition(
        assurance: &ActivationDocuments,
        transition: &SignedAdmissionWire<GenerationTransitionRequest>,
    ) -> serde_json::Value {
        serde_json::json!({
            "kind": "generation",
            "request": {
                "kind": "transition",
                "assurance": {
                    "calibration": assurance.calibration,
                    "run": assurance.run,
                    "run_authority": assurance.run_authority,
                    "proof": assurance.proof,
                    "proof_authority": assurance.proof_authority,
                },
                "transition": transition,
            },
        })
    }

    /// Write inert installed public-key configuration for the administrative CLI.
    pub(crate) fn write_host_trust(&self) -> PathBuf {
        let path = self.root.join("host-trust.json");
        fs::write(
            &path,
            serde_json::to_vec_pretty(&self.host_trust)
                .expect("host trust configuration serializes"),
        )
        .expect("host trust configuration writes");
        path
    }
}

fn transition_action(kind: &str) -> GenerationTransitionAction {
    match kind {
        "activate" => GenerationTransitionAction::Activate,
        "rollback" => GenerationTransitionAction::Rollback,
        _ => panic!("only activation and rollback are generation transitions"),
    }
}

impl Drop for ReferenceFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn fixture_signing_key(kind: ReferenceInstitutionKind, role_seed: u8) -> SigningKey {
    let institution_offset = match kind {
        ReferenceInstitutionKind::SoftwareDevelopment => 0,
        ReferenceInstitutionKind::Analytics => 0x50,
    };
    SigningKey::from_bytes(&[role_seed + institution_offset; 32])
}

fn anchor(
    principal: &PrincipalId,
    key: &SigningKey,
    permitted: impl IntoIterator<Item = AdmissionKind>,
) -> InstalledTrustAnchor {
    InstalledTrustAnchor {
        principal: principal.clone(),
        public_key: key.verifying_key().to_bytes(),
        permitted: permitted.into_iter().collect(),
    }
}

/// Materialize every byte named by the operational generation plan.
///
/// The archive and binary are copied from the checked-out public source and
/// the compiled test executable. The fixture verifies their identity, but it
/// does not run a second build and makes no executable-build reproducibility
/// claim; that limitation is explicit in the signed nondeterminism contract.
#[expect(
    clippy::expect_used,
    reason = "the acceptance fixture must fail loudly when public artifacts cannot be staged"
)]
fn stage_public_generation_material(
    root: &Path,
    source_document: &Path,
    executable: &Path,
    adapter: &AdapterId,
) -> ApprovedGenerationInputs {
    let repository = repository_root();
    let public_source = root.join("public-source.tar");
    git_archive(&repository, &public_source, None);
    let migrations = root.join("components/migrations.tar");
    git_archive(
        &repository,
        &migrations,
        Some("crates/politeia-storage/migrations"),
    );
    copy_public(executable, &root.join("components/executable"));
    copy_public(
        &repository.join("crates/politeiad/src/service.rs"),
        &root.join("components/execution_registry.rs"),
    );
    copy_public(
        &repository.join("spec/canonical-vectors.json"),
        &root.join("components/projections.json"),
    );
    copy_public(
        &repository.join("docs/22-DEPLOYMENT_PROFILES.md"),
        &root.join("components/compatibility.md"),
    );
    copy_public(
        &repository.join("Cargo.lock"),
        &root.join("components/update-metadata.cargo-lock"),
    );
    copy_public(
        &repository.join("docs/02-CONSTITUTION.md"),
        &root.join("policy/constitution.md"),
    );
    copy_public(
        &repository.join("crates/politeiad/src/artifacts.rs"),
        &root.join("specializer/artifacts.rs"),
    );
    copy_public(
        &repository.join("rust-toolchain.toml"),
        &root.join("toolchain/rust-toolchain.toml"),
    );
    copy_public(
        &repository.join("spec/semantic-operation.schema.json"),
        &root.join("schemas/semantic-operation.schema.json"),
    );
    copy_public(
        &repository.join("crates/politeiad/src/source.rs"),
        &root.join("adapters/source.rs"),
    );
    copy_public(
        source_document,
        &root.join("packs/reference-institution.md"),
    );

    let sbom = root.join("components/sbom.cargo-metadata.json");
    let metadata = Command::new("cargo")
        .current_dir(&repository)
        .args(["metadata", "--locked", "--format-version", "1"])
        .output()
        .expect("cargo metadata starts for public dependency metadata");
    assert!(
        metadata.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&metadata.stderr)
    );
    let parsed_metadata: serde_json::Value =
        serde_json::from_slice(&metadata.stdout).expect("cargo metadata is JSON");
    fs::write(
        &sbom,
        serde_json::to_vec_pretty(&serde_json::json!({
            "kind": "cargo_metadata_v1",
            "metadata": parsed_metadata,
        }))
        .expect("dependency metadata serializes"),
    )
    .expect("dependency metadata writes");

    let revision = Command::new("git")
        .current_dir(&repository)
        .args(["rev-parse", "HEAD"])
        .output()
        .expect("git revision lookup starts");
    assert!(
        revision.status.success(),
        "public source revision is available"
    );
    let provenance = root.join("components/provenance.json");
    fs::write(
        &provenance,
        serde_json::to_vec_pretty(&serde_json::json!({
            "kind": "fixture_public_artifact_provenance_v1",
            "source_revision": String::from_utf8(revision.stdout)
                .expect("revision is UTF-8")
                .trim(),
            "source_archive_digest": Digest::blake3(&fs::read(&public_source).expect("archive reads")),
            "executable_digest": Digest::blake3(&fs::read(root.join("components/executable")).expect("executable reads")),
            "claim": "exact bytes are verified; executable build reproducibility is not claimed",
        }))
        .expect("provenance serializes"),
    )
    .expect("provenance writes");
    let reproducibility = root.join("reproducibility-contract.md");
    fs::write(
        &reproducibility,
        "This fixture verifies immutable staged artifact bytes. It does not rebuild the copied politeia executable, so executable build reproducibility is not claimed.\n",
    )
    .expect("reproducibility limitation writes");

    ApprovedGenerationInputs {
        source_digest: digest_file(&public_source),
        lifecycle: LifecycleProfile::Operational,
        topology: DeploymentTopology::ClientControlledSingleTenant,
        schema_digests: BTreeMap::from([(
            "semantic-operation".to_owned(),
            digest_file(&root.join("schemas/semantic-operation.schema.json")),
        )]),
        adapter_digests: BTreeMap::from([(
            adapter.clone(),
            digest_file(&root.join("adapters/source.rs")),
        )]),
        pack_digests: BTreeMap::from([(
            "reference-institution".to_owned(),
            digest_file(&root.join("packs/reference-institution.md")),
        )]),
        component_digests: BTreeMap::from([
            (
                "executable".to_owned(),
                digest_file(&root.join("components/executable")),
            ),
            ("migrations".to_owned(), digest_file(&migrations)),
            (
                "execution_registry".to_owned(),
                digest_file(&root.join("components/execution_registry.rs")),
            ),
            (
                "projections".to_owned(),
                digest_file(&root.join("components/projections.json")),
            ),
            (
                "compatibility".to_owned(),
                digest_file(&root.join("components/compatibility.md")),
            ),
            ("sbom".to_owned(), digest_file(&sbom)),
            ("provenance".to_owned(), digest_file(&provenance)),
            (
                "update_metadata".to_owned(),
                digest_file(&root.join("components/update-metadata.cargo-lock")),
            ),
        ]),
        excluded_commissioning_capabilities: BTreeSet::from([
            CommissioningCapability::GenericReconnaissance,
            CommissioningCapability::InstitutionAuthoring,
            CommissioningCapability::AdapterDevelopment,
            CommissioningCapability::PolicyAuthoring,
            CommissioningCapability::GenerationDerivation,
        ]),
        specializer_digest: digest_file(&root.join("specializer/artifacts.rs")),
        toolchain_digest: digest_file(&root.join("toolchain/rust-toolchain.toml")),
        reproducibility: ReproducibilityContract::DeclaredNondeterminism {
            fields: BTreeSet::from(["components.executable".to_owned()]),
            contract_digest: digest_file(&reproducibility),
        },
    }
}

fn git_archive(repository: &Path, destination: &Path, path: Option<&str>) {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).expect("archive parent creates");
    }
    let mut command = Command::new("git");
    command
        .current_dir(repository)
        .args(["archive", "--format=tar", "--output"])
        .arg(destination)
        .arg("HEAD");
    if let Some(path) = path {
        command.arg(path);
    }
    let output = command.output().expect("git archive starts");
    assert!(
        output.status.success(),
        "git archive failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn copy_public(source: &Path, destination: &Path) {
    let parent = destination
        .parent()
        .expect("fixture destination has parent");
    fs::create_dir_all(parent).expect("fixture artifact parent creates");
    fs::copy(source, destination).expect("public artifact copies");
}

fn copy_tree(source: &Path, destination: &Path) {
    assert!(
        !destination.exists(),
        "artifact staging never overwrites a workspace path"
    );
    fs::create_dir_all(destination).expect("artifact staging root creates");
    for entry in fs::read_dir(source).expect("artifact source directory reads") {
        let entry = entry.expect("artifact source directory entry reads");
        let target = destination.join(entry.file_name());
        let file_type = entry.file_type().expect("artifact source file type reads");
        if file_type.is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            assert!(
                file_type.is_file(),
                "artifact input cannot be a symlink or special file"
            );
            fs::copy(entry.path(), target).expect("artifact input copies");
        }
    }
}

fn digest_file(path: &Path) -> Digest {
    Digest::blake3(&fs::read(path).expect("staged public artifact is readable"))
}

fn artifact_source_paths(adapter: &AdapterId) -> serde_json::Value {
    let mut adapters = serde_json::Map::new();
    adapters.insert(
        adapter.0.to_string(),
        serde_json::json!("generation/adapters/source.rs"),
    );
    serde_json::json!({
        "public_source": "generation/public-source.tar",
        "policy": "generation/policy/constitution.md",
        "specializer": "generation/specializer/artifacts.rs",
        "toolchain": "generation/toolchain/rust-toolchain.toml",
        "schemas": {"semantic-operation": "generation/schemas/semantic-operation.schema.json"},
        "adapters": adapters,
        "packs": {"reference-institution": "generation/packs/reference-institution.md"},
        "components": {
            "executable": "generation/components/executable",
            "migrations": "generation/components/migrations.tar",
            "execution_registry": "generation/components/execution_registry.rs",
            "projections": "generation/components/projections.json",
            "compatibility": "generation/components/compatibility.md",
            "sbom": "generation/components/sbom.cargo-metadata.json",
            "provenance": "generation/components/provenance.json",
            "update_metadata": "generation/components/update-metadata.cargo-lock",
        },
    })
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("politeiad manifest is nested below repository root")
        .to_path_buf()
}
