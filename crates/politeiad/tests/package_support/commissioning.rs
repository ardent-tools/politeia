//! Owner-signed commissioning inputs; all admission still crosses the daemon.

#![expect(
    clippy::expect_used,
    reason = "fixture construction must fail on malformed signed inputs"
)]

use super::*;
use politeia_core::{
    commissioning::{
        ApprovedCommissioningSubject, commissioning_approval_subject_digest,
        commissioning_observation_set_digest, unresolved_obligations_digest,
    },
    evidence::TrustedEvidenceRegistry,
};

impl ReferenceFixture {
    /// Finish a prepared capture after its exact descriptor grant was admitted.
    /// The descriptor, source, manifest, and evidence identities stay fixed;
    /// source access is never represented as predating durable authority.
    pub(crate) fn capture_after_admission(&self, prepared: CaptureDocuments) -> CaptureDocuments {
        let mut capture: SignedAdmissionWire<SourceCaptureRequest> =
            serde_json::from_value(prepared.document["capture"].clone())
                .expect("capture wire decodes");
        let mut observation: SignedAdmissionWire<ObservationRequest> =
            serde_json::from_value(prepared.document["observation"].clone())
                .expect("observation wire decodes");
        let mut evidence: SignedAdmissionWire<EvidenceRequest> =
            serde_json::from_value(prepared.document["evidence"].clone())
                .expect("evidence wire decodes");
        let now = Timestamp::now();
        capture.payload.observed_at = now;
        observation.payload.observed_at = now;
        evidence.payload.observed_at = now;
        evidence.payload.payload_digest = observation_evidence_payload_digest(
            &self.host_trust.workspace.id,
            &observation.payload,
        )
        .expect("refreshed observation evidence binds");
        let sign_capture = SignedAdmissionWire::sign(
            AdmissionKind::SourceCapture,
            self.host_trust.workspace.institution.clone(),
            self.host_trust.workspace.id.clone(),
            self.identities.commissioner.clone(),
            capture.payload,
            self.identities.commissioner_key(),
        )
        .expect("commissioner signs the capture after admission");
        let sign_observation = SignedAdmissionWire::sign(
            AdmissionKind::Observation,
            self.host_trust.workspace.institution.clone(),
            self.host_trust.workspace.id.clone(),
            self.identities.commissioner.clone(),
            observation.payload,
            self.identities.commissioner_key(),
        )
        .expect("commissioner signs the observation after admission");
        let sign_evidence = SignedAdmissionWire::sign(
            AdmissionKind::Evidence,
            self.host_trust.workspace.institution.clone(),
            self.host_trust.workspace.id.clone(),
            self.identities.commissioner.clone(),
            evidence.payload,
            self.identities.commissioner_key(),
        )
        .expect("commissioner signs the evidence after admission");
        CaptureDocuments {
            document: serde_json::json!({
                "capture": sign_capture, "evidence": sign_evidence,
                "observation": sign_observation,
                "reconnaissance": prepared.document["reconnaissance"],
            }),
            capture: sign_capture.payload,
            evidence: sign_evidence.payload.id,
            observation: sign_observation.payload,
        }
    }

    /// Construct each typed owner approval over the exact admitted observation set.
    pub(crate) fn commissioning_approvals(
        &self,
        capture: &CaptureDocuments,
    ) -> Vec<SignedAdmissionWire<EvidenceRequest>> {
        let workspace = &self.host_trust.workspace;
        let capture_evidence: SignedAdmissionWire<EvidenceRequest> =
            serde_json::from_value(capture.document["evidence"].clone())
                .expect("capture evidence decodes");
        let anchors = self
            .host_trust
            .anchors()
            .expect("installed public anchors reconstruct");
        let evidence = TrustedEvidenceRegistry::admit_signed(&anchors, [capture_evidence])
            .expect("actual capture evidence re-admits through public core");
        let observed = evidence
            .resolve(&capture.evidence)
            .expect("capture evidence resolves")
            .clone();
        let observations = commissioning_observation_set_digest(&[observed])
            .expect("exact observation set digests");
        let subjects = [
            ApprovedCommissioningSubject::InstitutionalModel {
                digest: workspace.approved_model_digest.clone(),
            },
            ApprovedCommissioningSubject::PolicyBundle {
                id: workspace.policy_bundle.clone(),
                digest: workspace.policy_digest.clone(),
            },
            ApprovedCommissioningSubject::GenerationInputs {
                digest: workspace
                    .approved_generation
                    .digest()
                    .expect("approved inputs digest"),
            },
            ApprovedCommissioningSubject::UnresolvedObligations {
                digest: unresolved_obligations_digest(
                    &workspace.institution,
                    &workspace.id,
                    &BTreeSet::new(),
                )
                .expect("empty explicit obligations digest"),
            },
        ];
        subjects
            .into_iter()
            .map(|approved| {
                let subject = commissioning_approval_subject_digest(
                    &workspace.institution,
                    &workspace.id,
                    &approved,
                    &observations,
                )
                .expect("typed owner approval subject binds exact observations");
                let payload_digest = Digest::blake3(
                    &politeia_core::canonical::to_canonical_bytes(&approved)
                        .expect("typed approval bytes encode"),
                );
                SignedAdmissionWire::sign(
                    AdmissionKind::Evidence,
                    workspace.institution.clone(),
                    workspace.id.clone(),
                    self.identities.owner.clone(),
                    EvidenceRequest {
                        id: EvidenceId::new(),
                        subject,
                        producer_delegation: workspace.owner_delegation.clone(),
                        method: "institution-owner commissioning approval.v1".to_owned(),
                        payload_digest,
                        observed_at: Timestamp::now(),
                        independence: IndependenceClass::HumanAuthority,
                    },
                    self.identities.owner_key(),
                )
                .expect("owner signs an exact commissioning approval")
            })
            .collect()
    }
}
