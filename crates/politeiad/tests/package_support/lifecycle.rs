//! Inert lifecycle-control documents for the process acceptance fixture.
//!
//! The daemon returns unsigned validation facts.  This helper only lets the
//! separately installed producer and verifier sign those exact facts under
//! owner-signed direct grants; it never selects a result or mints authority.

use jiff::{SignedDuration, Timestamp};
use politeia_core::{
    DataClass, Delegation, DelegationId, Digest, Effect, EvidenceId, ResourceBudget,
    canonical::to_canonical_bytes,
    trust::{AdmissionKind, SignedAdmissionWire},
};
use politeia_evidence::assurance::{
    ActivationProof, ControlRun, RUN_POLICY_CONTROL_ACTION, VERIFY_POLICY_CONTROL_ACTION,
    policy_control_resource,
};
use politeiad::service_generation_validation::GenerationValidationReport;

use super::{ActivationDocuments, ReferenceFixture};

/// Exact owner-signed direct authorities for one lifecycle control invocation.
pub(crate) struct LifecycleAuthorities {
    /// Grant carried with the control producer's signed run.
    pub(crate) run_authority: SignedAdmissionWire<Delegation>,
    /// Grant carried with the independent verifier's signed proof.
    pub(crate) proof_authority: SignedAdmissionWire<Delegation>,
}

impl ReferenceFixture {
    /// Create owner-signed direct grants for the persistent control producer
    /// and independent verifier for one exact named lifecycle control.
    pub(crate) fn lifecycle_authorities(&self, control: &str) -> LifecycleAuthorities {
        let run = self.lifecycle_authority(
            &self.identities.control_producer,
            RUN_POLICY_CONTROL_ACTION,
            control,
        );
        let proof = self.lifecycle_authority(
            &self.identities.verifier,
            VERIFY_POLICY_CONTROL_ACTION,
            control,
        );
        LifecycleAuthorities {
            run_authority: self.sign_owner_delegation(run),
            proof_authority: self.sign_owner_delegation(proof),
        }
    }

    /// Sign two independently requested but byte-identical public validation
    /// reports into the assurance shape consumed by activation.
    ///
    /// The reports must come from separate daemon `validate` responses.  All
    /// control, policy, vector, outcome, and coverage fields are copied rather
    /// than selected by this fixture.
    pub(crate) fn lifecycle_assurance(
        &self,
        producer_report: &GenerationValidationReport,
        verifier_report: &GenerationValidationReport,
        authority_wires: &LifecycleAuthorities,
        started_at: Timestamp,
    ) -> ActivationDocuments {
        assert_eq!(
            producer_report, verifier_report,
            "control producer and verifier must sign the same daemon validation report"
        );
        assert_ne!(
            self.identities.control_producer, self.identities.verifier,
            "lifecycle producer and verifier must remain independent"
        );
        let report = producer_report;
        let authorization = Digest::blake3(
            &to_canonical_bytes(&authority_wires.run_authority.payload)
                .expect("owner-signed direct grant canonically encodes"),
        );
        let run = ControlRun {
            id: EvidenceId::new(),
            control: report.control.clone(),
            control_version: report.control_version.clone(),
            configuration_digest: report.artifact_manifest.clone(),
            policy: report.policy.clone(),
            policy_digest: report.policy_digest.clone(),
            input_digest: report.generation.clone(),
            subject: report.generation.clone(),
            population: report.population.clone(),
            authorization,
            mediation_path: report.mediation_path.clone(),
            started_at: started_at.clone(),
            finished_at: started_at.clone(),
            result: report.known_good_result,
            coverage: report.coverage,
        };
        let proof = ActivationProof {
            id: EvidenceId::new(),
            control: report.control.clone(),
            control_version: report.control_version.clone(),
            configuration_digest: report.artifact_manifest.clone(),
            policy: report.policy.clone(),
            policy_digest: report.policy_digest.clone(),
            population: report.population.clone(),
            mediation_path: report.mediation_path.clone(),
            planted_violation: report.planted_violation.clone(),
            planted_violation_result: report.planted_violation_result,
            known_good: report.known_good.clone(),
            known_good_result: report.known_good_result,
            retained_evidence: EvidenceId::new(),
            proved_at: started_at,
        };
        ActivationDocuments {
            run: SignedAdmissionWire::sign(
                AdmissionKind::ControlRun,
                self.host_trust.workspace.institution.clone(),
                self.host_trust.workspace.id.clone(),
                self.identities.control_producer.clone(),
                run,
                self.identities.control_producer_key(),
            )
            .expect("control producer signs exact daemon report"),
            run_authority: authority_wires.run_authority.clone(),
            proof: SignedAdmissionWire::sign(
                AdmissionKind::ActivationProof,
                self.host_trust.workspace.institution.clone(),
                self.host_trust.workspace.id.clone(),
                self.identities.verifier.clone(),
                proof,
                self.identities.verifier_key(),
            )
            .expect("independent verifier signs exact daemon report"),
            proof_authority: authority_wires.proof_authority.clone(),
        }
    }

    fn lifecycle_authority(
        &self,
        subject: &politeia_core::PrincipalId,
        action: &str,
        control: &str,
    ) -> Delegation {
        Delegation {
            id: DelegationId::new(),
            issuer: self.identities.owner.clone(),
            subject: subject.clone(),
            parent: None,
            actions: std::collections::BTreeSet::from([action.to_owned()]),
            resources: std::collections::BTreeSet::from([policy_control_resource(control)]),
            effects: std::collections::BTreeSet::<Effect>::new(),
            data_classes: std::collections::BTreeSet::<DataClass>::new(),
            audience: std::collections::BTreeSet::from([format!(
                "institution:{}",
                self.host_trust.workspace.institution.0
            )]),
            expires_at: Timestamp::now() + SignedDuration::from_hours(1),
            budget: ResourceBudget {
                wall_ms: None,
                cpu_ms: None,
                memory_bytes: None,
                io_bytes: None,
                network_bytes: None,
                external_cost_microunits: None,
            },
        }
    }

    fn sign_owner_delegation(&self, delegation: Delegation) -> SignedAdmissionWire<Delegation> {
        SignedAdmissionWire::sign(
            AdmissionKind::Delegation,
            self.host_trust.workspace.institution.clone(),
            self.host_trust.workspace.id.clone(),
            self.identities.owner.clone(),
            delegation,
            self.identities.owner_key(),
        )
        .expect("owner signs direct lifecycle authority")
    }
}
