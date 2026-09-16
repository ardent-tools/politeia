//! Owner evidence documents for the durable operational-handoff receipt.

#![expect(
    clippy::expect_used,
    reason = "package evidence construction must fail loudly when canonical contracts drift"
)]

use jiff::Timestamp;
use politeia_core::{
    BudgetReservationId, Digest, EvidenceId, RuntimeGenerationId,
    evidence::{EvidenceRequest, IndependenceClass},
    trust::{AdmissionKind, SignedAdmissionWire},
};
use politeia_evidence::{
    commissioner_revocation_subject_digest, operational_continuity_subject_digest,
};
use politeiad::{
    service_generation::CommissioningReceipt,
    service_handoff::{HANDOFF_CONTINUITY_METHOD, HANDOFF_REVOCATION_METHOD, HandoffSubmission},
};

use super::ReferenceFixture;

/// Owner evidence captured after every original commissioner grant has ended.
///
/// This is deliberately a two-stage builder. The revocation statement must be
/// signed after the revocation responses and before the canary runs; continuity
/// is signed only after the CLI returns the canonical completed receipt.
pub(crate) struct HandoffRevocationEvidence {
    expected_generation: RuntimeGenerationId,
    revocation: SignedAdmissionWire<EvidenceRequest>,
}

impl ReferenceFixture {
    /// Sign owner acceptance of the exact ended grant from a daemon receipt.
    pub(crate) fn handoff_revocation_evidence(
        &self,
        generation: &Digest,
        commissioning: &CommissioningReceipt,
    ) -> HandoffRevocationEvidence {
        assert_eq!(
            commissioning.commissioner, self.identities.commissioner,
            "handoff must close the original installed commissioner"
        );
        let expected_generation = RuntimeGenerationId::from_digest(generation.clone());
        let subject = commissioner_revocation_subject_digest(
            &self.host_trust.workspace.institution,
            &self.host_trust.workspace.id,
            &commissioning.record,
            &commissioning.commissioner_grant_digest,
        )
        .expect("handoff revocation subject encodes");
        let revocation = self.sign_handoff_evidence(EvidenceRequest {
            id: EvidenceId::new(),
            subject,
            producer_delegation: self.host_trust.workspace.owner_delegation.clone(),
            method: HANDOFF_REVOCATION_METHOD.to_owned(),
            payload_digest: commissioning.commissioner_grant_digest.clone(),
            observed_at: Timestamp::now(),
            independence: IndependenceClass::HumanAuthority,
        });
        HandoffRevocationEvidence {
            expected_generation,
            revocation,
        }
    }

    /// Produce the intentionally incomplete transport shape for fail-closed proof.
    pub(crate) fn handoff_without_evidence(
        generation: &Digest,
        reservation: &BudgetReservationId,
    ) -> serde_json::Value {
        serde_json::json!({
            "kind": "handoff",
            "submission": {
                "expected_generation": RuntimeGenerationId::from_digest(generation.clone()),
                "continuity_reservation": reservation,
            },
        })
    }

    fn sign_handoff_evidence(
        &self,
        request: EvidenceRequest,
    ) -> SignedAdmissionWire<EvidenceRequest> {
        SignedAdmissionWire::sign(
            AdmissionKind::Evidence,
            self.host_trust.workspace.institution.clone(),
            self.host_trust.workspace.id.clone(),
            self.identities.owner.clone(),
            request,
            self.identities.owner_key(),
        )
        .expect("installed owner signs exact handoff evidence")
    }
}

impl HandoffRevocationEvidence {
    /// Sign continuity after a real completed canary and build daemon ingress.
    pub(crate) fn submission(
        &self,
        fixture: &ReferenceFixture,
        reservation: BudgetReservationId,
        canonical_receipt_digest: Digest,
    ) -> serde_json::Value {
        let subject = operational_continuity_subject_digest(
            &fixture.host_trust.workspace.institution,
            &fixture.host_trust.workspace.id,
            &self.expected_generation,
        )
        .expect("handoff continuity subject encodes");
        let continuity = fixture.sign_handoff_evidence(EvidenceRequest {
            id: EvidenceId::new(),
            subject,
            producer_delegation: fixture.host_trust.workspace.owner_delegation.clone(),
            method: HANDOFF_CONTINUITY_METHOD.to_owned(),
            payload_digest: canonical_receipt_digest,
            observed_at: Timestamp::now(),
            independence: IndependenceClass::HumanAuthority,
        });
        serde_json::json!({
            "kind": "handoff",
            "submission": HandoffSubmission {
                expected_generation: self.expected_generation.clone(),
                continuity_reservation: reservation,
                revocation_evidence: self.revocation.clone(),
                continuity_evidence: continuity,
            },
        })
    }
}
