//! Public CLI exercise of commissioner revocation, replacement, and rollback.

use std::{collections::BTreeSet, path::Path};

use jiff::Timestamp;
use politeia_core::{BudgetReservationId, Delegation, Digest};
use politeiad::service_generation::CommissioningReceipt;

use super::{
    CommissionedGeneration, OperationalFixture, ReferenceFixture, TestResult, require_coordinated,
    require_refusal, run, status_value, submit_commissioning, write_request,
};

use crate::package_support::operational::PLANTED_DENIAL_REASON;

/// Exercise commissioner handoff only through the installed CLI and daemon.
///
/// The original receipt remains historical provenance after revocation; live
/// publication authority is separately re-established for the replacement.
pub(super) fn exercise(
    database_url: &str,
    fixture: &ReferenceFixture,
    operations: &OperationalFixture,
    commissioned: &CommissionedGeneration,
    temporary_grants: &[Delegation],
) -> TestResult<Digest> {
    let prior_canary = positive_canary(database_url, fixture, operations, "pre-revocation")?;
    negative_canary(database_url, fixture, operations)?;
    let prior_reservation: BudgetReservationId =
        serde_json::from_value(prior_canary["reservation"].clone())?;
    let prior_receipt: Digest = serde_json::from_value(prior_canary["receipt_digest"].clone())?;
    let premature_handoff = fixture
        .handoff_revocation_evidence(&commissioned.generation, &commissioned.receipt)
        .submission(fixture, prior_reservation.clone(), prior_receipt.clone());
    refuse_handoff(
        database_url,
        fixture,
        "handoff-with-active-commissioner.json",
        &premature_handoff,
        "commissioner authority remains active for the workspace",
    )?;

    revoke_commissioner_authority(
        database_url,
        fixture,
        &commissioned.commissioner,
        temporary_grants,
    )?;
    require_refusal(
        run(
            database_url,
            &[
                Path::new("snapshot"),
                &fixture.prefix().join("run/politeiad.sock"),
                &fixture.root.join("corrected-active-capture.json"),
            ],
        )?,
        "revoked commissioner reconnaissance credential",
        "capture delegation is revoked before source access",
    )?;
    let ended_authority =
        fixture.handoff_revocation_evidence(&commissioned.generation, &commissioned.receipt);
    refuse_handoff(
        database_url,
        fixture,
        "handoff-with-pre-revocation-canary.json",
        &ended_authority.submission(fixture, prior_reservation, prior_receipt),
        "handoff canary receipt is not a completed active-generation local operation",
    )?;

    let verified = submit_commissioning(
        database_url,
        fixture,
        "verify-after-commissioner-revocation.json",
        &serde_json::json!({
            "kind": "generation",
            "request": { "kind": "verify", "generation": commissioned.generation },
        }),
    )?;
    assert_eq!(verified["verified"], true);
    let reproduced = submit_commissioning(
        database_url,
        fixture,
        "reproduce-after-commissioner-revocation.json",
        &serde_json::json!({
            "kind": "generation",
            "request": { "kind": "reproduce", "generation": commissioned.generation },
        }),
    )?;
    assert_eq!(reproduced["generation_reproduced"], true);

    let old_publication = write_request(
        fixture,
        "revoked-commissioner-publication.json",
        &commissioned.publication,
    )?;
    require_refusal(
        run(
            database_url,
            &[
                Path::new("commissioning"),
                &fixture.prefix().join("run/politeiad.sock"),
                &old_publication,
            ],
        )?,
        "revoked commissioner publication credential",
        "delegation is revoked",
    )?;
    let continuity = positive_canary(
        database_url,
        fixture,
        operations,
        "after-commissioner-revocation",
    )?;
    let reservation: BudgetReservationId =
        serde_json::from_value(continuity["reservation"].clone())?;
    let receipt: Digest = serde_json::from_value(continuity["receipt_digest"].clone())?;
    refuse_handoff(
        database_url,
        fixture,
        "handoff-without-owner-evidence.json",
        &ReferenceFixture::handoff_without_evidence(&commissioned.generation, &reservation),
        "missing field `revocation_evidence`",
    )?;
    let handed_off = submit_commissioning(
        database_url,
        fixture,
        "accept-operational-handoff.json",
        &ended_authority.submission(fixture, reservation.clone(), receipt.clone()),
    )?;
    assert_eq!(handed_off["completed"], true);
    assert_eq!(
        handed_off["generation"],
        serde_json::json!(commissioned.generation)
    );
    assert_eq!(
        handed_off["continuity_reservation"],
        serde_json::json!(reservation)
    );
    assert_eq!(
        handed_off["continuity_receipt_digest"],
        serde_json::json!(receipt)
    );
    let durable_handoff =
        super::continuity::observe_handoff_receipt(database_url, fixture, &handed_off)?;
    super::evidence::record_observation("accepted_operational_handoff", &durable_handoff)?;

    let replacement = fixture.replacement_delegation(&commissioned.owner_root);
    let unauthorized_publication =
        fixture.replacement_generation_documents(&replacement, &commissioned.receipt);
    require_refusal(
        run(
            database_url,
            &[
                Path::new("commissioning"),
                &fixture.prefix().join("run/politeiad.sock"),
                &write_request(
                    fixture,
                    "replacement-publication-without-grant.json",
                    &unauthorized_publication.publish,
                )?,
            ],
        )?,
        "replacement publication without a fresh durable grant",
        "delegation is not durably admitted",
    )?;

    let recommissioned = submit_commissioning(
        database_url,
        fixture,
        "replacement-recommission.json",
        &fixture.replacement_recommission_request(&replacement),
    )?;
    assert_eq!(recommissioned["recommissioned"], true);
    assert_eq!(
        recommissioned["delegation"],
        serde_json::json!(replacement.id)
    );

    assert_eq!(
        commissioned.receipt.observations.len(),
        1,
        "the reference package retains one exact discovery observation"
    );
    let observation = commissioned
        .receipt
        .observations
        .iter()
        .next()
        .expect("the asserted retained observation exists")
        .clone();
    let replacement_receipt: CommissioningReceipt = serde_json::from_value(submit_commissioning(
        database_url,
        fixture,
        "replacement-derive-record.json",
        &fixture.replacement_derive_record_request(
            &replacement,
            &observation,
            commissioned.receipt.approvals.clone(),
        ),
    )?)?;
    assert_eq!(
        replacement_receipt.commissioner,
        fixture.identities.replacement
    );
    assert_eq!(
        replacement_receipt.observations, commissioned.receipt.observations,
        "replacement receipt retains the original selected observation"
    );
    assert_eq!(
        replacement_receipt.approvals, commissioned.receipt.approvals,
        "replacement receipt retains the original owner approvals"
    );

    let replacement_publication =
        fixture.replacement_generation_documents(&replacement, &replacement_receipt);
    let published = submit_commissioning(
        database_url,
        fixture,
        "replacement-publish.json",
        &replacement_publication.publish,
    )?;
    let replacement_generation: Digest = serde_json::from_value(published["generation"].clone())?;
    assert_eq!(published["admitted"], true);
    let verified_replacement = submit_commissioning(
        database_url,
        fixture,
        "replacement-verify.json",
        &serde_json::json!({
            "kind": "generation",
            "request": { "kind": "verify", "generation": replacement_generation },
        }),
    )?;
    assert_eq!(verified_replacement["verified"], true);
    let reproduced_replacement = submit_commissioning(
        database_url,
        fixture,
        "replacement-reproduce.json",
        &serde_json::json!({
            "kind": "generation",
            "request": { "kind": "reproduce", "generation": replacement_generation },
        }),
    )?;
    assert_eq!(reproduced_replacement["generation_reproduced"], true);

    super::lifecycle::activate(
        database_url,
        fixture,
        &replacement_generation,
        "activate",
        true,
    )?;
    assert_eq!(
        status_value(database_url, fixture)?["active_generation"],
        serde_json::json!(replacement_generation)
    );
    positive_canary(database_url, fixture, operations, "replacement-active")?;

    super::lifecycle::activate(
        database_url,
        fixture,
        &commissioned.generation,
        "rollback",
        false,
    )?;
    assert_eq!(
        status_value(database_url, fixture)?["active_generation"],
        serde_json::json!(commissioned.generation)
    );
    positive_canary(database_url, fixture, operations, "rollback-active")?;
    Ok(replacement_generation)
}

fn refuse_handoff(
    database_url: &str,
    fixture: &ReferenceFixture,
    name: &str,
    document: &serde_json::Value,
    reason: &str,
) -> TestResult {
    require_refusal(
        run(
            database_url,
            &[
                Path::new("commissioning"),
                &fixture.prefix().join("run/politeiad.sock"),
                &write_request(fixture, name, document)?,
            ],
        )?,
        name,
        reason,
    )
}

fn revoke_commissioner_authority(
    database_url: &str,
    fixture: &ReferenceFixture,
    publication: &Delegation,
    temporary_grants: &[Delegation],
) -> TestResult {
    let mut grants = temporary_grants.to_vec();
    if !grants.iter().any(|grant| grant.id == publication.id) {
        grants.push(publication.clone());
    }
    let mut revoked = BTreeSet::new();
    for (index, grant) in grants.into_iter().enumerate() {
        if !revoked.insert(grant.id.clone()) {
            continue;
        }
        assert_eq!(
            grant.subject, fixture.identities.commissioner,
            "handoff revokes only temporary commissioner authority, never the owner root"
        );
        let admitted = fixture.signed_commissioner_delegation(grant);
        let revoked = submit_commissioning(
            database_url,
            fixture,
            &format!("revoke-commissioner-grant-{index}.json"),
            &fixture.owner_revocation_request(
                &admitted,
                format!("handoff replaces temporary commissioner authority #{index}"),
            ),
        )?;
        assert_eq!(revoked["revoked"], true);
    }
    Ok(())
}

fn positive_canary(
    database_url: &str,
    fixture: &ReferenceFixture,
    operations: &OperationalFixture,
    stage: &str,
) -> TestResult<serde_json::Value> {
    let routed_at = Timestamp::now();
    let prepared = operations.positive_manifest(fixture, routed_at);
    let expected_remote_rejections = serde_json::to_value(operations.remote_rejections(routed_at))?;
    submit_commissioning(
        database_url,
        fixture,
        &format!("{stage}-canary-authority.json"),
        &prepared.authority_admission,
    )?;
    let response = require_coordinated(
        run(
            database_url,
            &[
                Path::new("operate"),
                &fixture.prefix().join("run/politeiad.sock"),
                &write_request(
                    fixture,
                    &format!("{stage}-canary-operate.json"),
                    &prepared.operate,
                )?,
            ],
        )?,
        &format!("{stage} local deterministic operational canary"),
    )?;
    assert_eq!(
        response["manifest"]["resources"],
        serde_json::json!(["public:approved-operation"]),
        "the selected local execution resource returned the actual bounded manifest"
    );
    assert_eq!(
        response["routing"]["outcome"]["resource"],
        prepared.operate["routing"]["outcome"]["resource"],
        "the daemon selected the exact locally eligible resource from the signed routing receipt"
    );
    assert_eq!(
        response["routing"]["rejected_resources"],
        prepared.operate["routing"]["rejected_resources"],
        "the daemon retained every hard rejection from the signed routing receipt"
    );
    let rejected = response["routing"]["rejected_resources"]
        .as_object()
        .expect("completed routing exposes its rejected resource map");
    let supplied_rejections = prepared.operate["routing"]["rejected_resources"]
        .as_object()
        .expect("signed routing receipt exposes its rejected resource map");
    let remote_resource = supplied_rejections
        .iter()
        .find_map(|(resource, reasons)| {
            (reasons == &expected_remote_rejections).then_some(resource)
        })
        .expect("signed routing receipt names the cheaper remote resource");
    assert!(
        rejected.get(remote_resource) == Some(&expected_remote_rejections),
        "the daemon response proves the cheaper remote resource was rejected for its exact hard constraints"
    );
    for field in ["receipt", "receipt_digest", "reservation", "outbox"] {
        assert!(
            response[field]
                .as_str()
                .is_some_and(|value| !value.is_empty()),
            "the completed protected operation returns a nonempty canonical {field} identity"
        );
    }
    Ok(response)
}

fn negative_canary(
    database_url: &str,
    fixture: &ReferenceFixture,
    operations: &OperationalFixture,
) -> TestResult {
    let prepared = operations.negative_manifest(fixture, Timestamp::now());
    submit_commissioning(
        database_url,
        fixture,
        "planted-policy-canary-authority.json",
        &prepared.authority_admission,
    )?;
    require_refusal(
        run(
            database_url,
            &[
                Path::new("operate"),
                &fixture.prefix().join("run/politeiad.sock"),
                &write_request(
                    fixture,
                    "planted-policy-canary-operate.json",
                    &prepared.operate,
                )?,
            ],
        )?,
        "planted public resource policy canary",
        PLANTED_DENIAL_REASON,
    )?;
    Ok(())
}
