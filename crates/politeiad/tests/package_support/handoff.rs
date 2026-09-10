//! Public-process handoff documents for revocation and replacement commissioning.

#![expect(
    clippy::expect_used,
    reason = "fixture construction must fail when an exact public contract drifts"
)]

use std::collections::BTreeSet;

use politeia_core::{
    Delegation, Digest, EvidenceId,
    canonical::to_canonical_bytes,
    generation::RuntimeGenerationInputs,
    trust::{AdmissionKind, SignedAdmissionWire},
};
use politeiad::{
    service_generation::CommissioningReceipt, service_revocation::DelegationRevocationRequest,
};

use super::*;

impl ReferenceFixture {
    /// Construct the installed owner's revocation of one exact durably-admitted grant.
    ///
    /// The daemon resolves the delegation again from durable state, but this
    /// document pre-binds the same canonical payload digest so a delegation ID
    /// cannot be redirected to a different signed grant.
    pub(crate) fn owner_revocation_request(
        &self,
        admitted: &SignedAdmissionWire<Delegation>,
        reason: impl Into<String>,
    ) -> serde_json::Value {
        assert_eq!(admitted.kind, AdmissionKind::Delegation);
        assert_eq!(
            admitted.institution, self.host_trust.workspace.institution,
            "revocation can only name this fixture institution"
        );
        assert_eq!(
            admitted.workspace, self.host_trust.workspace.id,
            "revocation can only name this fixture workspace"
        );
        assert_eq!(
            admitted.signer, self.identities.owner,
            "the supplied admitted delegation must be owner-signed"
        );
        let request = DelegationRevocationRequest {
            delegation: admitted.payload.id.clone(),
            delegation_digest: Digest::blake3(
                &to_canonical_bytes(&admitted.payload)
                    .expect("admitted delegation canonical bytes encode"),
            ),
            evidence: EvidenceId::new(),
            reason: reason.into(),
        };
        let request = SignedAdmissionWire::sign(
            AdmissionKind::Revocation,
            self.host_trust.workspace.institution.clone(),
            self.host_trust.workspace.id.clone(),
            self.identities.owner.clone(),
            request,
            self.identities.owner_key(),
        )
        .expect("owner signs exact delegation revocation");
        serde_json::json!({ "kind": "revoke_delegation", "request": request })
    }

    /// Construct a fresh owner-rooted replacement grant admission request.
    ///
    /// This does not grant authority locally. The daemon must re-admit the
    /// owner signature and validate attenuation against the durable root.
    pub(crate) fn replacement_recommission_request(
        &self,
        replacement: &Delegation,
    ) -> serde_json::Value {
        self.assert_replacement(replacement);
        serde_json::json!({
            "kind": "generation",
            "request": {
                "kind": "recommission",
                "delegation": SignedAdmissionWire::sign(
                    AdmissionKind::Delegation,
                    self.host_trust.workspace.institution.clone(),
                    self.host_trust.workspace.id.clone(),
                    self.identities.owner.clone(),
                    replacement.clone(),
                    self.identities.owner_key(),
                ).expect("owner signs replacement delegation"),
            },
        })
    }

    /// Construct a new commissioning-record request under the replacement's
    /// durably-admitted delegation and newly captured observation evidence.
    ///
    /// Owner approval wires are submitted separately through the public
    /// `commissioning_approval` ingress; this request names their exact
    /// resulting evidence identities and never invents a receipt.
    pub(crate) fn replacement_derive_record_request(
        &self,
        replacement: &Delegation,
        observation: EvidenceId,
        approvals: impl IntoIterator<Item = EvidenceId>,
    ) -> serde_json::Value {
        self.assert_replacement(replacement);
        let approvals = approvals.into_iter().collect::<BTreeSet<_>>();
        serde_json::json!({
            "kind": "generation",
            "request": {
                "kind": "derive_record",
                "selection": {
                    "delegation": replacement.id,
                    "observations": [observation],
                    "approvals": approvals,
                    "unresolved_obligations": [],
                },
            },
        })
    }

    /// Build a publish request signed by the fresh replacement identity.
    ///
    /// The receipt remains the daemon-issued historical record supplied by the
    /// caller. Publication authority is separately bound to the replacement
    /// delegation, and the old commissioner key is never used here.
    pub(crate) fn replacement_generation_documents(
        &self,
        replacement: &Delegation,
        receipt: &CommissioningReceipt,
    ) -> GenerationDocuments {
        self.assert_replacement(replacement);
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
            self.identities.replacement.clone(),
            inputs,
            self.identities.replacement_key(),
        )
        .expect("replacement signs generation inputs");
        let publish = serde_json::json!({
            "kind": "generation",
            "request": {
                "kind": "publish",
                "inputs": inputs,
                "commissioning": {
                    "receipt": receipt,
                    "publication_delegation": replacement.id,
                },
                "sources": artifact_source_paths(&self.adapter),
            },
        });
        GenerationDocuments { inputs, publish }
    }

    fn assert_replacement(&self, replacement: &Delegation) {
        assert_eq!(
            replacement.subject, self.identities.replacement,
            "replacement request must be signed by the installed replacement identity"
        );
        assert_ne!(
            replacement.subject, self.identities.commissioner,
            "the revoked commissioner must never sign replacement publication"
        );
    }
}
