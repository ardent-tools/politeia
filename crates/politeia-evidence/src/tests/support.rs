#![expect(
    clippy::expect_used,
    reason = "fixed cryptographic test fixtures must fail immediately when malformed"
)]

use std::collections::BTreeSet;

use ed25519_dalek::SigningKey;
use jiff::{SignedDuration, Timestamp};
use politeia_core::trust::{
    AdmissionError, AdmissionKind, Admitted, InstitutionTrustAnchors, SignedAdmissionWire,
    TrustedSigningKey,
};
use politeia_core::{
    DataClass, Delegation, Effect, InstitutionId, InstitutionWorkspaceId, PrincipalId,
    ResourceBudget,
};
use serde::Serialize;

use crate::authority::{AuthorityContext, institution_audience};

pub(crate) struct TestAuthority {
    pub(crate) institution: InstitutionId,
    pub(crate) workspace: InstitutionWorkspaceId,
    pub(crate) owner: PrincipalId,
    pub(crate) producer: PrincipalId,
    pub(crate) verifier: PrincipalId,
    owner_key: SigningKey,
    producer_key: SigningKey,
    verifier_key: SigningKey,
    anchors: InstitutionTrustAnchors,
    now: Timestamp,
}

impl TestAuthority {
    pub(crate) fn new() -> Self {
        let institution = InstitutionId::new();
        let workspace = InstitutionWorkspaceId::new();
        let owner = PrincipalId::new();
        let producer = PrincipalId::new();
        let verifier = PrincipalId::new();
        let owner_key = SigningKey::from_bytes(&[11; 32]);
        let producer_key = SigningKey::from_bytes(&[22; 32]);
        let verifier_key = SigningKey::from_bytes(&[33; 32]);
        let permissions = BTreeSet::from([
            AdmissionKind::Delegation,
            AdmissionKind::ControlRun,
            AdmissionKind::ActivationProof,
            AdmissionKind::Verification,
        ]);
        let keys = [
            TrustedSigningKey::new(
                owner.clone(),
                owner_key.verifying_key().to_bytes(),
                permissions.clone(),
            )
            .expect("owner key is valid"),
            TrustedSigningKey::new(
                producer.clone(),
                producer_key.verifying_key().to_bytes(),
                permissions.clone(),
            )
            .expect("producer key is valid"),
            TrustedSigningKey::new(
                verifier.clone(),
                verifier_key.verifying_key().to_bytes(),
                permissions,
            )
            .expect("verifier key is valid"),
        ];
        let anchors = InstitutionTrustAnchors::from_trusted_bootstrap(
            institution.clone(),
            workspace.clone(),
            keys,
        )
        .expect("fixture principals are unique");
        Self {
            institution,
            workspace,
            owner,
            producer,
            verifier,
            owner_key,
            producer_key,
            verifier_key,
            anchors,
            now: "2026-08-21T00:00:00Z"
                .parse()
                .expect("fixture timestamp is RFC 3339"),
        }
    }

    pub(crate) fn now(&self) -> Timestamp {
        self.now
    }

    pub(crate) fn context(&self) -> AuthorityContext {
        AuthorityContext::new(
            self.institution.clone(),
            self.workspace.clone(),
            self.owner.clone(),
            self.now,
        )
    }

    pub(crate) fn grant(&self, subject: PrincipalId, action: &str, resource: String) -> Delegation {
        Delegation {
            id: politeia_core::DelegationId::new(),
            issuer: self.owner.clone(),
            subject,
            parent: None,
            actions: BTreeSet::from([action.to_string()]),
            resources: BTreeSet::from([resource]),
            effects: BTreeSet::<Effect>::new(),
            data_classes: BTreeSet::<DataClass>::new(),
            audience: BTreeSet::from([institution_audience(&self.institution)]),
            expires_at: self.now + SignedDuration::from_hours(1),
            budget: ResourceBudget {
                wall_ms: Some(0),
                cpu_ms: Some(0),
                memory_bytes: Some(0),
                io_bytes: Some(0),
                network_bytes: Some(0),
                external_cost_microunits: Some(0),
            },
        }
    }

    pub(crate) fn sign<T: Serialize>(
        &self,
        kind: AdmissionKind,
        signer: &PrincipalId,
        payload: T,
    ) -> SignedAdmissionWire<T> {
        SignedAdmissionWire::sign(
            kind,
            self.institution.clone(),
            self.workspace.clone(),
            signer.clone(),
            payload,
            self.key(signer),
        )
        .expect("fixture payload canonically encodes")
    }

    pub(crate) fn admit<T: Serialize>(
        &self,
        kind: AdmissionKind,
        signer: &PrincipalId,
        payload: T,
    ) -> Admitted<T> {
        self.anchors
            .admit_expected(kind, self.sign(kind, signer, payload))
            .expect("fixture signature and scope are valid")
    }

    pub(crate) fn admit_wire<T: Serialize>(
        &self,
        expected: AdmissionKind,
        wire: SignedAdmissionWire<T>,
    ) -> Result<Admitted<T>, AdmissionError> {
        self.anchors.admit_expected(expected, wire)
    }

    fn key(&self, signer: &PrincipalId) -> &SigningKey {
        if signer == &self.owner {
            &self.owner_key
        } else if signer == &self.producer {
            &self.producer_key
        } else {
            assert_eq!(
                signer, &self.verifier,
                "fixture signer must be one of the installed principals"
            );
            &self.verifier_key
        }
    }
}
