//! Strict recovery of the exact evidence and reconnaissance closure named by a receipt.

use std::collections::{BTreeMap, BTreeSet};

use politeia_core::{
    EvidenceId, SourceCaptureId,
    evidence::{EvidenceRequest, TrustedEvidenceRegistry},
    knowledge::{ObservationRequest, SourceCaptureRequest},
    trust::{AdmissionKind, InstitutionTrustAnchors, SignedAdmissionWire},
};
use politeia_storage::{SignedRecord, WorkspaceSnapshot};
use serde_json::Value;

use crate::{CoordinatorError, service::state_wire};

/// Re-admit only evidence identities explicitly selected by a commissioning receipt.
///
/// The durable journal also retains control runs and activation proofs. They are
/// immutable provenance, but not `EvidenceRequest` statements, so interpreting
/// the whole journal as one evidence registry would make an unrelated activation
/// alter a historical commissioning record.
pub(super) fn selected_evidence(
    anchors: &InstitutionTrustAnchors,
    journal: &BTreeMap<EvidenceId, SignedRecord>,
    observations: &BTreeSet<EvidenceId>,
    approvals: &BTreeSet<EvidenceId>,
) -> Result<TrustedEvidenceRegistry, CoordinatorError> {
    let selected = observations
        .iter()
        .chain(approvals)
        .cloned()
        .collect::<BTreeSet<_>>();
    let wires = selected
        .iter()
        .map(|id| selected_evidence_wire(anchors, journal, id))
        .collect::<Result<Vec<_>, _>>()?;
    TrustedEvidenceRegistry::admit_signed(anchors, wires).map_err(super::refusal)
}

/// Recover the signed observation-to-capture closure for selected evidence.
///
/// Observation state has no index by evidence identity. We therefore inspect
/// each typed observation entry strictly to find the requested identity, but
/// only return and later admit the selected closure. Any malformed entry under
/// the observation namespace is a durable-state integrity failure, never a
/// reason to silently omit a possible dependency.
pub(super) fn selected_reconnaissance_wires(
    durable: &WorkspaceSnapshot,
    evidence_ids: &BTreeSet<EvidenceId>,
) -> Result<
    (
        Vec<SignedAdmissionWire<SourceCaptureRequest>>,
        Vec<SignedAdmissionWire<ObservationRequest>>,
    ),
    CoordinatorError,
> {
    let mut selected_observations = BTreeMap::new();
    for (key, payload) in &durable.state {
        if !key.starts_with("observation:") {
            continue;
        }
        let wire: SignedAdmissionWire<ObservationRequest> = state_wire(payload)?;
        if wire.kind != AdmissionKind::Observation {
            return Err(CoordinatorError::Refused(
                "durable observation state has the wrong admission kind".to_string(),
            ));
        }
        if key != &format!("observation:{}", wire.payload.id.0) {
            return Err(CoordinatorError::Refused(
                "durable observation state key differs from its signed identity".to_string(),
            ));
        }
        if evidence_ids.contains(&wire.payload.evidence)
            && selected_observations
                .insert(wire.payload.evidence.clone(), wire)
                .is_some()
        {
            return Err(CoordinatorError::Refused(
                "commissioning evidence has ambiguous retained signed observations".to_string(),
            ));
        }
    }
    for evidence_id in evidence_ids {
        if !selected_observations.contains_key(evidence_id) {
            return Err(CoordinatorError::Refused(
                "commissioning evidence has no retained signed observation".to_string(),
            ));
        }
    }

    let mut captures =
        BTreeMap::<SourceCaptureId, SignedAdmissionWire<SourceCaptureRequest>>::new();
    for observation in selected_observations.values() {
        let capture_id = &observation.payload.capture;
        let key = format!("source_capture:{}", capture_id.0);
        let payload = durable.state.get(&key).ok_or_else(|| {
            CoordinatorError::Refused(
                "commissioning observation has no retained signed capture".to_string(),
            )
        })?;
        let capture: SignedAdmissionWire<SourceCaptureRequest> = state_wire(payload)?;
        if capture.kind != AdmissionKind::SourceCapture {
            return Err(CoordinatorError::Refused(
                "durable source capture state has the wrong admission kind".to_string(),
            ));
        }
        if capture.payload.id != *capture_id {
            return Err(CoordinatorError::Refused(
                "durable source capture state key differs from its signed identity".to_string(),
            ));
        }
        captures.insert(capture_id.clone(), capture);
    }
    Ok((
        captures.into_values().collect(),
        selected_observations.into_values().collect(),
    ))
}

fn selected_evidence_wire(
    anchors: &InstitutionTrustAnchors,
    journal: &BTreeMap<EvidenceId, SignedRecord>,
    id: &EvidenceId,
) -> Result<SignedAdmissionWire<EvidenceRequest>, CoordinatorError> {
    let record = journal.get(id).ok_or_else(|| {
        CoordinatorError::Refused(
            "commissioning receipt names evidence absent from durable admission".to_string(),
        )
    })?;
    let envelope: SignedAdmissionWire<Value> =
        serde_json::from_slice(record.payload()).map_err(|_| {
            CoordinatorError::Refused(
                "selected commissioning evidence is not a signed envelope".to_string(),
            )
        })?;
    if envelope.signer != *record.signer() || envelope.signature != record.signature() {
        return Err(CoordinatorError::Refused(
            "selected commissioning evidence differs from its durable signature".to_string(),
        ));
    }
    if envelope.kind != AdmissionKind::Evidence {
        return Err(CoordinatorError::Refused(
            "selected commissioning evidence has the wrong admission kind".to_string(),
        ));
    }
    let wire: SignedAdmissionWire<EvidenceRequest> = serde_json::from_slice(record.payload())
        .map_err(|_| {
            CoordinatorError::Refused(
                "selected commissioning evidence has the wrong payload type".to_string(),
            )
        })?;
    if wire.payload.id != *id {
        return Err(CoordinatorError::Refused(
            "selected commissioning evidence identity differs from its journal key".to_string(),
        ));
    }
    // Verify the actual typed statement here, so a generic envelope cannot
    // turn an invalid selected wire into historical evidence.
    anchors
        .admit_expected(AdmissionKind::Evidence, wire.clone())
        .map_err(super::refusal)?;
    Ok(wire)
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::expect_used,
        reason = "fixtures must fail loudly when durable provenance changes"
    )]

    use std::collections::{BTreeMap, BTreeSet};

    use ed25519_dalek::SigningKey;
    use jiff::Timestamp;
    use politeia_core::{
        DelegationId, Digest, EvidenceId, InstitutionId, InstitutionWorkspaceId, PolicyBundleId,
        PrincipalId,
        evidence::{EvidenceRequest, IndependenceClass},
        trust::{AdmissionKind, InstitutionTrustAnchors, SignedAdmissionWire, TrustedSigningKey},
    };
    use politeia_evidence::assurance::{ActivationProof, ControlResult, ControlRun, Coverage};
    use politeia_storage::SignedRecord;
    use serde::Serialize;

    use super::selected_evidence;

    struct Fixture {
        anchors: InstitutionTrustAnchors,
        institution: InstitutionId,
        workspace: InstitutionWorkspaceId,
        principal: PrincipalId,
        key: SigningKey,
    }

    fn fixture() -> Fixture {
        let institution = InstitutionId::new();
        let workspace = InstitutionWorkspaceId::new();
        let principal = PrincipalId::new();
        let key = SigningKey::from_bytes(&[9; 32]);
        let anchors = InstitutionTrustAnchors::from_trusted_bootstrap(
            institution.clone(),
            workspace.clone(),
            [TrustedSigningKey::new(
                principal.clone(),
                key.verifying_key().to_bytes(),
                BTreeSet::from([
                    AdmissionKind::Evidence,
                    AdmissionKind::ControlRun,
                    AdmissionKind::ActivationProof,
                ]),
            )
            .expect("fixture key is valid")],
        )
        .expect("fixture anchor is unique");
        Fixture {
            anchors,
            institution,
            workspace,
            principal,
            key,
        }
    }

    fn record<T: Serialize>(wire: &SignedAdmissionWire<T>) -> SignedRecord {
        SignedRecord::from_json(
            &serde_json::to_value(wire).expect("wire encodes"),
            wire.signer.clone(),
            wire.signature.clone(),
        )
        .expect("wire records")
    }

    fn evidence(fixture: &Fixture) -> SignedAdmissionWire<EvidenceRequest> {
        SignedAdmissionWire::sign(
            AdmissionKind::Evidence,
            fixture.institution.clone(),
            fixture.workspace.clone(),
            fixture.principal.clone(),
            EvidenceRequest {
                id: EvidenceId::new(),
                subject: Digest::blake3(b"commissioning-subject"),
                producer_delegation: DelegationId::new(),
                method: "fixture evidence".to_string(),
                payload_digest: Digest::blake3(b"fixture payload"),
                observed_at: Timestamp::now(),
                independence: IndependenceClass::IndependentService,
            },
            &fixture.key,
        )
        .expect("evidence signs")
    }

    fn control_run(fixture: &Fixture) -> SignedAdmissionWire<ControlRun> {
        SignedAdmissionWire::sign(
            AdmissionKind::ControlRun,
            fixture.institution.clone(),
            fixture.workspace.clone(),
            fixture.principal.clone(),
            ControlRun {
                id: EvidenceId::new(),
                control: "generation:activate".to_string(),
                control_version: "fixture-v1".to_string(),
                configuration_digest: Digest::blake3(b"configuration"),
                policy: PolicyBundleId::new(),
                policy_digest: Digest::blake3(b"policy"),
                input_digest: Digest::blake3(b"input"),
                subject: Digest::blake3(b"subject"),
                population: Digest::blake3(b"population"),
                authorization: Digest::blake3(b"authorization"),
                mediation_path: "unix-socket".to_string(),
                started_at: Timestamp::now(),
                finished_at: Timestamp::now(),
                result: ControlResult::Clean,
                coverage: Coverage {
                    population: 1,
                    observed: 1,
                },
            },
            &fixture.key,
        )
        .expect("control run signs")
    }

    fn activation_proof(fixture: &Fixture) -> SignedAdmissionWire<ActivationProof> {
        SignedAdmissionWire::sign(
            AdmissionKind::ActivationProof,
            fixture.institution.clone(),
            fixture.workspace.clone(),
            fixture.principal.clone(),
            ActivationProof {
                id: EvidenceId::new(),
                control: "generation:activate".to_string(),
                control_version: "fixture-v1".to_string(),
                configuration_digest: Digest::blake3(b"configuration"),
                policy: PolicyBundleId::new(),
                policy_digest: Digest::blake3(b"policy"),
                population: Digest::blake3(b"population"),
                mediation_path: "unix-socket".to_string(),
                planted_violation: Digest::blake3(b"violation"),
                planted_violation_result: ControlResult::Violation,
                known_good: Digest::blake3(b"good"),
                known_good_result: ControlResult::Clean,
                retained_evidence: EvidenceId::new(),
                proved_at: Timestamp::now(),
            },
            &fixture.key,
        )
        .expect("activation proof signs")
    }

    #[test]
    fn selected_evidence_ignores_unrelated_genuine_activation_records() {
        let fixture = fixture();
        let evidence = evidence(&fixture);
        let run = control_run(&fixture);
        let proof = activation_proof(&fixture);
        fixture
            .anchors
            .admit_expected(AdmissionKind::ControlRun, run.clone())
            .expect("run is a genuine signed control record");
        fixture
            .anchors
            .admit_expected(AdmissionKind::ActivationProof, proof.clone())
            .expect("proof is a genuine signed activation record");
        let durable = evidence_journal([
            (evidence.payload.id.clone(), record(&evidence)),
            (run.payload.id.clone(), record(&run)),
            (proof.payload.id.clone(), record(&proof)),
        ]);

        let registry = selected_evidence(
            &fixture.anchors,
            &durable,
            &BTreeSet::from([evidence.payload.id.clone()]),
            &BTreeSet::new(),
        )
        .expect("unrelated activation evidence does not alter a selected receipt");
        assert!(registry.resolve(&evidence.payload.id).is_some());
    }

    #[test]
    fn selected_non_evidence_kind_refuses_even_when_its_wire_is_genuine() {
        let fixture = fixture();
        let run = control_run(&fixture);
        let durable = evidence_journal([(run.payload.id.clone(), record(&run))]);

        let error = selected_evidence(
            &fixture.anchors,
            &durable,
            &BTreeSet::from([run.payload.id.clone()]),
            &BTreeSet::new(),
        )
        .expect_err("a selected control run cannot stand in for commissioning evidence");
        assert!(
            error
                .to_string()
                .contains("selected commissioning evidence has the wrong admission kind")
        );
    }

    fn evidence_journal(
        evidence: impl IntoIterator<Item = (EvidenceId, SignedRecord)>,
    ) -> BTreeMap<EvidenceId, SignedRecord> {
        evidence.into_iter().collect()
    }
}
