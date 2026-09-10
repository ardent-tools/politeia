//! Inert lifecycle-control documents for the process acceptance fixture.
//!
//! The daemon returns unsigned validation facts. This helper lets separately
//! installed producer and verifier principals sign those facts under exact
//! owner-issued grants, while preserving the verifier calibration before the
//! later producer control run starts.

use jiff::{SignedDuration, Timestamp};
use politeia_core::{
    DataClass, Delegation, DelegationId, Digest, Effect, EvidenceId, ResourceBudget,
    canonical::to_canonical_bytes,
    evidence::{EvidenceRequest, IndependenceClass},
    trust::{AdmissionKind, SignedAdmissionWire},
};
use politeia_evidence::assurance::{
    ActivationProof, ControlRun, RUN_POLICY_CONTROL_ACTION, VERIFY_POLICY_CONTROL_ACTION,
    policy_control_resource,
};
use politeiad::service_generation_validation::{
    GenerationValidationReport, LIFECYCLE_CALIBRATION_METHOD,
};

use super::{ActivationDocuments, ReferenceFixture};

/// Exact owner-signed direct authorities for one lifecycle control invocation.
pub(crate) struct LifecycleAuthorities {
    /// Grant carried with the control producer's signed run.
    pub(crate) run_authority: SignedAdmissionWire<Delegation>,
    /// Grant carried with the independent verifier's signed proof and calibration.
    pub(crate) proof_authority: SignedAdmissionWire<Delegation>,
}

/// Verifier-signed calibration material retained by a later activation proof.
pub(crate) struct LifecycleCalibration {
    report: GenerationValidationReport,
    evidence: SignedAdmissionWire<EvidenceRequest>,
    proof: SignedAdmissionWire<ActivationProof>,
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

    /// Sign verifier calibration evidence and proof immediately after the
    /// verifier's first actual daemon validation response.
    pub(crate) fn lifecycle_calibration(
        &self,
        verifier_report: &GenerationValidationReport,
        authority_wires: &LifecycleAuthorities,
    ) -> LifecycleCalibration {
        assert_ne!(
            self.identities.control_producer, self.identities.verifier,
            "lifecycle producer and verifier must remain independent"
        );
        let calibrated_at = Timestamp::now();
        let report_digest = verifier_report
            .digest()
            .expect("daemon validation report canonically encodes");
        let evidence = EvidenceRequest {
            id: EvidenceId::new(),
            subject: report_digest.clone(),
            producer_delegation: authority_wires.proof_authority.payload.id.clone(),
            method: LIFECYCLE_CALIBRATION_METHOD.to_owned(),
            payload_digest: report_digest,
            observed_at: calibrated_at,
            independence: IndependenceClass::IndependentAgent,
        };
        let proof = ActivationProof {
            id: EvidenceId::new(),
            control: verifier_report.control.clone(),
            control_version: verifier_report.control_version.clone(),
            configuration_digest: verifier_report.artifact_manifest.clone(),
            policy: verifier_report.policy.clone(),
            policy_digest: verifier_report.policy_digest.clone(),
            population: verifier_report.population.clone(),
            mediation_path: verifier_report.mediation_path.clone(),
            planted_violation: verifier_report.planted_violation.clone(),
            planted_violation_result: verifier_report.planted_violation_result,
            known_good: verifier_report.known_good.clone(),
            known_good_result: verifier_report.known_good_result,
            retained_evidence: evidence.id.clone(),
            proved_at: calibrated_at,
        };
        LifecycleCalibration {
            report: verifier_report.clone(),
            evidence: SignedAdmissionWire::sign(
                AdmissionKind::Evidence,
                self.host_trust.workspace.institution.clone(),
                self.host_trust.workspace.id.clone(),
                self.identities.verifier.clone(),
                evidence,
                self.identities.verifier_key(),
            )
            .expect("independent verifier signs lifecycle calibration"),
            proof: SignedAdmissionWire::sign(
                AdmissionKind::ActivationProof,
                self.host_trust.workspace.institution.clone(),
                self.host_trust.workspace.id.clone(),
                self.identities.verifier.clone(),
                proof,
                self.identities.verifier_key(),
            )
            .expect("independent verifier signs calibration proof"),
        }
    }

    /// Sign a producer control run after a second actual daemon validation
    /// response, reusing calibration made by the independent verifier first.
    pub(crate) fn lifecycle_assurance(
        &self,
        producer_report: &GenerationValidationReport,
        calibration: &LifecycleCalibration,
        authority_wires: &LifecycleAuthorities,
        started_at: Timestamp,
    ) -> ActivationDocuments {
        assert_eq!(
            producer_report, &calibration.report,
            "control producer and verifier must receive identical daemon validation reports"
        );
        assert_eq!(
            calibration.evidence.payload.producer_delegation,
            authority_wires.proof_authority.payload.id,
            "calibration must remain bound to the verifier authority submitted for activation"
        );
        assert!(
            calibration.proof.payload.proved_at <= started_at,
            "the verifier proof must predate the producer control run"
        );
        let completed_at = Timestamp::now();
        assert!(
            completed_at >= started_at,
            "the producer control run cannot finish before the caller observed it starting"
        );
        let authorization = Digest::blake3(
            &to_canonical_bytes(&authority_wires.run_authority.payload)
                .expect("owner-signed direct grant canonically encodes"),
        );
        let run = ControlRun {
            id: EvidenceId::new(),
            control: producer_report.control.clone(),
            control_version: producer_report.control_version.clone(),
            configuration_digest: producer_report.artifact_manifest.clone(),
            policy: producer_report.policy.clone(),
            policy_digest: producer_report.policy_digest.clone(),
            input_digest: producer_report.generation.clone(),
            subject: producer_report.generation.clone(),
            population: producer_report.population.clone(),
            authorization,
            mediation_path: producer_report.mediation_path.clone(),
            started_at,
            finished_at: completed_at,
            result: producer_report.known_good_result,
            coverage: producer_report.coverage,
        };
        ActivationDocuments {
            calibration: calibration.evidence.clone(),
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
            proof: calibration.proof.clone(),
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
